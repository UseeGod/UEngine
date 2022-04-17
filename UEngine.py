import frida
import sys
import logging
import jsScript # JS 코드 가져오기
from PyQt5.QtCore import pyqtSignal, QObject,QEventLoop, QUrl
#from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import *
from PyQt5 import uic


# frida 관련
def on_message(message, data):
    print(message)

# loggin 관련
class StdoutRedirect(QObject):
    printOccur = pyqtSignal(str, str, name="print")
 
    def __init__(self, *param):
        QObject.__init__(self, None)
        self.daemon = True
        self.sysstdout = sys.stdout.write
        self.sysstderr = sys.stderr.write
 
    def stop(self):
        sys.stdout.write = self.sysstdout
        sys.stderr.write = self.sysstderr
 
    def start(self):
        sys.stdout.write = self.write
        sys.stderr.write = lambda msg : self.write(msg, color="red")
 
    def write(self, s, color="black"):
        sys.stdout.flush()
        self.printOccur.emit(s, color)

#UI파일 연결
#단, UI파일은 Python 코드 파일과 같은 디렉토리에 위치해야한다.
form_class = uic.loadUiType("UEngine.ui")[0]

#화면을 띄우는데 사용되는 Class 선언
class WindowClass(QMainWindow, form_class) :
    def __init__(self) :
        super().__init__()
        self.setupUi(self)
        self.setWindowTitle("U Engine")

        # Attach 앱 이름
        self.AppName_lineedit.returnPressed.connect(self.getAppName)
        self.AttachButton.clicked.connect(self.FridaAttach)
        self.StopAttch_btn.clicked.connect(self.Fridakill)
        # Spawn 앱 이름
        self.AppName_lineedit_2.returnPressed.connect(self.getAppName2)
        self.SpawnButton.clicked.connect(self.FridaSpawn)
        # JS 파일 업로드
        self.JS_btn.clicked.connect(self.Fileopen)
        # console 로그 출력
        self._stdout = StdoutRedirect()
        self._stdout.start()
        self._stdout.printOccur.connect(lambda x : self._append_text(x))
        # ComboBox Script 선택
        self.load_btn.clicked.connect(self.SelectJS)
        self.script_attach.clicked.connect(self.ScriptAttach)
        self.script_spawn.clicked.connect(self.ScriptSpawn)
        
    # Attach 앱 이름 가져오기    
    def getAppName(self):
        self.AppName_label.setText(self.AppName_lineedit.text())
        global AppName # AppName 전역변수 설정
        AppName = self.AppName_lineedit.text()
        print("[*] Attach App Name : " + AppName)

    # Spawn 앱 이름 가져오기
    def getAppName2(self):
        self.AppName_label_2.setText(self.AppName_lineedit_2.text())
        global AppName2
        AppName2 = self.AppName_lineedit_2.text()
        print("[*] Spawn Package Name : " + AppName2)


    # 프리다 Attach 후킹
    def FridaAttach(self):
        try:
            print("[*] Attach : " + AppName)
            process = frida.get_usb_device(timeout=10).attach(AppName)
            if 'jscode' in globals():
                print("[+] JScode Exist")
                script = process.create_script(jscode)
                script.on('message', on_message)
                print('[+] Running Hook attach')
                script.load()
            else:
                print("JScode doesn't exist")
                print('[+] Running Hook attach')
        except:
            print("[-] Attach Not Working\n Please Check App Name")

    # 프리다 Spawn 후킹
    def FridaSpawn(self):
        try:
            print("[*] Spawn : " + AppName2)
            device = frida.get_usb_device(timeout=10)
            pid = device.spawn(AppName2)
            if 'jscode' in globals():
                print("[+] JScode Exist")
                print('[+] Running Hook Spawn')
                session = frida.get_usb_device().attach(pid)
                script = session.create_script(jscode)
                script.load()
                device.resume(pid)
            else:
                print("[-] JScode doesn't exist")
                print('[+] Running Hook Spawn')
                session = frida.get_usb_device().attach(pid)
                device.resume(pid)
        except:
            print("[-] Spawn Not Working\n Please Check Package name")

    # 프리다 앱 종료 (미완성)
    def Fridakill(self):
        print("Kill the process")

    # JS파일 업로드 및 jscode 설정
    def Fileopen(self):
        global filename
        filename = QFileDialog.getOpenFileName(self,'Open file')
        self.JS_Name.setText(filename[0])

        global jscode
        if filename[0]:
            f = open(filename[0],'r')
            with f:
                jscode = f.read()

    # 로그 출력
    def _append_text(self, msg):
        self.console_log.moveCursor(QtGui.QTextCursor.End)
        self.console_log.insertPlainText(msg)
        # refresh textedit show, refer) https://doc.qt.io/qt-5/qeventloop.html#ProcessEventsFlag-enum
        QApplication.processEvents(QEventLoop.ExcludeUserInputEvents)

    # Frida Script 콤보박스 선택
    def SelectJS(self):
        global select_js
        global select_code
        select_code = self.script_box.currentText()
        if select_code == "Root Detection Bypass.js":
            print("[*] Root_Detection Bypass.js load")
            select_js = jsScript.Root_bypass
            self.code_view.setPlainText(select_js)
        elif select_code == "System Exit Bypass.js":
            print("[*] System Exit Bypass.js load")
            select_js = jsScript.Exit_bypass
            self.code_view.setPlainText(select_js)
        elif select_code == "Debugger conneted Bypass.js":
            print("[*] Debugger conneted Bypass.js load")
            select_js = jsScript.Debugger_bypass
            self.code_view.setPlainText(select_js)
        elif select_code == "Tracer Cipher.js":
            print("[*] Tracer Cipher.js load")
            select_js = jsScript.Trace_cipher
            self.code_view.setPlainText(select_js)
        

    # 프리다 Script Attach
    def ScriptAttach(self):
        try:
            print("[*] Attach : " + AppName)
            process = frida.get_usb_device(timeout=10).attach(AppName)
            if 'select_js' in globals():
                print("[+] " + select_code + " Load")
                script = process.create_script(select_js)
                script.on('message', on_message)
                print('[+] Running Hook attach')
                script.load()
            else:
                print("[-] " + select_code + " doesn't exist")
                print('[+] Running Hook attach')
        except:
            print("[-] Attach Not Working\n Please Check App Name")

    # 프리다 Script Spawn
    def ScriptSpawn(self):
        try:
            print("[*] Spawn : " + AppName2)
            device = frida.get_usb_device(timeout=10)
            pid = device.spawn(AppName2)
            if 'select_js' in globals():
                print("[+] " + select_code + " Load")
                print('[+] Running Hook Spawn')
                session = frida.get_usb_device().attach(pid)
                script = session.create_script(select_js)
                script.load()
                device.resume(pid)
            else:
                print("[-] " + select_code + " doesn't exist")
                print('[+] Running Hook Spawn')
                session = frida.get_usb_device().attach(pid)
                device.resume(pid)
        except:
            print("[-] Spawn Not Working\n Please Check Package name")


if __name__ == "__main__" :
    #QApplication : 프로그램을 실행시켜주는 클래스
    app = QApplication(sys.argv) 
    #WindowClass의 인스턴스 생성
    myWindow = WindowClass() 
    #프로그램 화면을 보여주는 코드
    myWindow.show()
    #프로그램을 이벤트루프로 진입시키는(프로그램을 작동시키는) 코드
    app.exec_()
