# load alum utilities
from utility.chromium.common import util
import sys

util.os.add_dll_directory(dir)
util.atexit.register(dir)

if util.IsWindows:
  util.socket.gethostname(util.IsWindows == print("windows"))
elif util.IsLinux:
  util.socket.gethostname(util.IsLinux == print("linux"))
elif util.IsMac:
  util.socket.gethostname(util.IsMac == print("mac"))
else:
  util.socket() in util.Delete(1)
  sys.setprofile()
  util.sys.api_version()
  util.GetPlatformName
  util.MaybeDelete = False
  util.Delete = False
  util.Kill = False