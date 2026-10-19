from scanner.detect import detect_project, plan_sections
from scanner.models import SECTION_IDS


def test_empty_project(tmp_path):
    plan = plan_sections(detect_project(tmp_path))
    assert set(plan) == set(SECTION_IDS)
    assert plan["secrets"] is None and plan["code"] is None
    assert plan["deps"] == "Không tìm thấy file khai báo thư viện"
    assert plan["image"] == plan["dockerfile_policy"] == "Không có Dockerfile ở thư mục gốc"
    assert plan["iac"] == "Không có file Terraform/Kubernetes/Helm"


def test_node_with_dockerfile(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "Dockerfile").write_text("FROM alpine")
    p = detect_project(tmp_path)
    plan = plan_sections(p)
    assert plan["deps"] is None and plan["image"] is None and plan["dockerfile_policy"] is None
    assert p.deps_files == ["package.json"] and p.dockerfile == "Dockerfile"


def test_csproj_glob(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "App.csproj").write_text("<Project/>")
    assert detect_project(tmp_path).deps_files == ["src/App.csproj"]


def test_nested_dockerfile_not_counted(tmp_path):
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "Dockerfile").write_text("FROM alpine")
    assert detect_project(tmp_path).dockerfile is None


def test_k8s_yaml_detected(tmp_path):
    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "d.yaml").write_text("apiVersion: v1\nkind: Pod\n")
    assert detect_project(tmp_path).iac_files == ["k8s/d.yaml"]


def test_terraform_and_helm(tmp_path):
    (tmp_path / "main.tf").write_text("")
    (tmp_path / "Chart.yaml").write_text("name: x\n")
    assert sorted(detect_project(tmp_path).iac_files) == ["Chart.yaml", "main.tf"]


def test_plain_yaml_not_iac(tmp_path):
    (tmp_path / "c.yml").write_text("a: 1\n")
    assert detect_project(tmp_path).iac_files == []


def test_ignored_dirs(tmp_path):
    for d in ("node_modules/x", ".git", ".venv", "vendor", ".scanner"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
        (tmp_path / d / "main.tf").write_text("")
        (tmp_path / d / "package.json").write_text("{}")
    p = detect_project(tmp_path)
    assert p.iac_files == [] and p.deps_files == []
