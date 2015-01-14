import os

EXE_NAME='3dmovie.exe'
KEY_PATH=r'SOFTWARE\Microsoft\Microsoft Kids\3D Movie Maker'

try:
	import _winreg as reg
	def getInstallDirectory():
		with reg.OpenKey(reg.HKEY_LOCAL_MACHINE,KEY_PATH) as hKey:
			return reg.QueryValueEx(hKey,'InstallDirectory')[0]

	def get3DMovieMakerPath():
		with reg.OpenKey(reg.HKEY_LOCAL_MACHINE,KEY_PATH) as hKey:
			installDirectory = reg.QueryValueEx(hKey,'InstallDirectory')[0]
			installSubDir = reg.QueryValueEx(hKey,'InstallSubDir')[0]
			return os.path.join(installDirectory, installSubDir)

	def getInstalledEXEPath():
		return os.path.join(get3DMovieMakerPath(),EXE_NAME)
except ImportError: # we're probably running on linux! so stub these out
	def getInstallDirectory():
		raise OSError("Non-windows OS: can't check registry")

	def get3DMovieMakerPath():
		raise OSError("Non-windows OS: can't check registry")

	def getInstalledEXEPath():
		raise OSError("Non-windows OS: can't check registry")


def getAnyEXE():
	if os.path.exists(EXE_NAME):
		return EXE_NAME
	else:
		return getInstalledEXEPath()

if __name__=='__main__':
	print getAnyEXE()