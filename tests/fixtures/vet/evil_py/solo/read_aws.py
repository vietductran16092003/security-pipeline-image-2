import os

creds = open(os.path.expanduser("~/.aws/credentials")).read()
print(len(creds))
