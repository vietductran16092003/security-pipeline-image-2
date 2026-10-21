const fs = require("fs");
fs.mkdirSync("dist", { recursive: true });
fs.writeFileSync("dist/ok.txt", "built");
