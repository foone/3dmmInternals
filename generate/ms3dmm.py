import _winreg as reg
import os

KEY_PATH=r'SOFTWARE\Microsoft\Microsoft Kids\3D Movie Maker'

def getInstallDirectory():
	with reg.OpenKey(reg.HKEY_LOCAL_MACHINE,KEY_PATH) as hKey:
		return reg.QueryValueEx(hKey,'InstallDirectory')[0]

def get3DMovieMakerPath():
	with reg.OpenKey(reg.HKEY_LOCAL_MACHINE,KEY_PATH) as hKey:
		installDirectory = reg.QueryValueEx(hKey,'InstallDirectory')[0]
		installSubDir = reg.QueryValueEx(hKey,'InstallSubDir')[0]
		return os.path.join(installDirectory, installSubDir)

def getEXEPath():
	return os.path.join(get3DMovieMakerPath(),'3dmovie.exe')

if __name__=='__main__':
	print get3DMovieMakerPath()