# Root Detection Bypass
Root_bypass = """
/*
Original author: Daniele Linguaglossa
28/07/2021 -    Edited by Simone Quatrini
                Code amended to correctly run on the latest frida version
        		Added controls to exclude Magisk Manager
*/

Java.perform(function () {
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
    ];

    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"];

    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    };

    var RootPropertiesKeys = [];

    for (var k in RootProperties) RootPropertiesKeys.push(k);

    var PackageManager = Java.use("android.app.ApplicationPackageManager");

    var Runtime = Java.use('java.lang.Runtime');

    var NativeFile = Java.use('java.io.File');

    var String = Java.use('java.lang.String');

    var SystemProperties = Java.use('android.os.SystemProperties');

    var BufferedReader = Java.use('java.io.BufferedReader');

    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

    var StringBuffer = Java.use('java.lang.StringBuffer');

    var loaded_classes = Java.enumerateLoadedClassesSync();

    send("Loaded " + loaded_classes.length + " classes!");

    var useKeyInfo = false;

    var useProcessManager = false;

    send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

    if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
        try {
            //useProcessManager = true;
            //var ProcessManager = Java.use('java.lang.ProcessManager');
        } catch (err) {
            send("ProcessManager Hook failed: " + err);
        }
    } else {
        send("ProcessManager hook not loaded");
    }

    var KeyInfo = null;

    if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
        try {
            //useKeyInfo = true;
            //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
        } catch (err) {
            send("KeyInfo Hook failed: " + err);
        }
    } else {
        send("KeyInfo hook not loaded");
    }

    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            send("Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
    };

    NativeFile.exists.implementation = function () {
        var name = NativeFile.getName.call(this);
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
        if (shouldFakeReturn) {
            send("Bypass return value for binary: " + name);
            return false;
        } else {
            return this.exists.call(this);
        }
    };

    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

    exec5.implementation = function (cmd, env, dir) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec5.call(this, cmd, env, dir);
    };

    exec4.implementation = function (cmdarr, env, file) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec4.call(this, cmdarr, env, file);
    };

    exec3.implementation = function (cmdarr, envp) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec3.call(this, cmdarr, envp);
    };

    exec2.implementation = function (cmd, env) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec2.call(this, cmd, env);
    };

    exec.implementation = function (cmd) {
        for (var i = 0; i < cmd.length; i = i + 1) {
            var tmp_cmd = cmd[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
        }

        return exec.call(this, cmd);
    };

    exec1.implementation = function (cmd) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec1.call(this, cmd);
    };

    String.contains.implementation = function (name) {
        if (name == "test-keys") {
            send("Bypass test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };

    var get = SystemProperties.get.overload('java.lang.String');

    get.implementation = function (name) {
        if (RootPropertiesKeys.indexOf(name) != -1) {
            send("Bypass " + name);
            return RootProperties[name];
        }
        return this.get.call(this, name);
    };

    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function (args) {
            var path = Memory.readCString(args[0]);
            path = path.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/notexists");
                send("Bypass native fopen");
            }
        },
        onLeave: function (retval) {

        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function (args) {
            var cmd = Memory.readCString(args[0]);
            send("SYSTEM CMD: " + cmd);
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "grep");
            }
            if (cmd == "su") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
            }
        },
        onLeave: function (retval) {

        }
    });

    /*

    TO IMPLEMENT:

    Exec Family

    int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
    int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
    int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execv(const char *path, char *const argv[]);
    int execve(const char *path, char *const argv[], char *const envp[]);
    int execvp(const char *file, char *const argv[]);
    int execvpe(const char *file, char *const argv[], char *const envp[]);

    */


    BufferedReader.readLine.overload('boolean').implementation = function () {
        var text = this.readLine.overload('boolean').call(this);
        if (text === null) {
            // just pass , i know it's ugly as hell but test != null won't work :(
        } else {
            var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
            if (shouldFakeRead) {
                send("Bypass build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
        }
        return text;
    };

    var executeCommand = ProcessBuilder.command.overload('java.util.List');

    ProcessBuilder.start.implementation = function () {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        for (var i = 0; i < cmd.size(); i = i + 1) {
            var tmp_cmd = cmd.get(i).toString();
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                shouldModifyCommand = true;
            }
        }
        if (shouldModifyCommand) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        if (cmd.indexOf("su") != -1) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
            return this.start.call(this);
        }

        return this.start.call(this);
    };

    if (useProcessManager) {
        var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
        var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

        ProcManExec.implementation = function (cmd, env, workdir, redirectstderr) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
        };

        ProcManExecVariant.implementation = function (cmd, env, directory, stdin, stdout, stderr, redirect) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
        };
    }

    if (useKeyInfo) {
        KeyInfo.isInsideSecureHardware.implementation = function () {
            send("Bypass isInsideSecureHardware");
            return true;
        }
    }

});
"""

#Debugger conneted bypass
Debugger_bypass = """
Java.perform(function () {
    send("--> isDebuggerConnected - Bypass Loaded")
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () {
        send("isDebuggerConnected - bypass done!");
        return false;
    }
});
"""


# System Exit Bypass
Exit_bypass = """
Java.perform(function () {
    const System = Java.use('java.lang.System')

    send("--> System.exit() Bypass - Script Loaded")
    System.exit.implementation = function(){
        send("System.exit() Bypassed!");
    }
});
"""


# Trace cipher
Trace_cipher = """
/****************************************************************************************************************************
 * Name: Cipher class hooks and utilities
 * OS: Android
 * Author: FSecureLABS
 * Source: https://github.com/FSecureLABS/android-keystore-audit/blob/master/frida-scripts/tracer-cipher.js
 * Info: 
	Hooks will attempt to trace calls to Cipher class and hexdump buffer passed/returned during encryption/decryption.
	All instances of Cipher class are captured by hooking any getInstance() call. You can them it in the cipherList variable.
	Utilities:
	ListCiphers()
	* List Cipher instances collected in cipherList
	GetCipher(cipherName)
	* Get Cipher instance from cipherList using it's name 
	* example: GetCipher("javax.crypto.Cipher@b6859ee")
	doUpdate(cipherName, bytes)
	* Call doUpdate on Cipher instance from cipherList using it's name
	* you can pass buffer into it which will be processed.
	* The bytes buffer must be Java [B
	* Example: doUpdate('javax.crypto.Cipher@b6859ee', buffer)
	doFinal(cipherName)
	* Call doFinal on Cipher instance from cipherList using it's name
	* Example: doFinal('javax.crypto.Cipher@b6859ee')
*****************************************************************************************************************************/


send("Cipher hooks loaded!");

Java.perform(function () {
    hookCipherGetInstance();
    hookCipherGetInstance2();
    hookCipherGetInstance3();
    hookCipherInit();
    hookCipherInit2();
    hookCipherInit3();
    hookCipherInit4();
    hookCipherInit5();
    hookCipherInit6();
    hookCipherInit7();
    hookCipherInit8();
    hookDoFinal();
    hookDoFinal2();
    hookDoFinal3();
    hookDoFinal4();
    hookDoFinal5();
    hookDoFinal6();
    hookDoFinal7();
    hookUpdate();
    hookUpdate2();
    hookUpdate3();
    hookUpdate4();
    hookUpdate5();


});



var cipherList = [];
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');


});

/*
    .overload('java.lang.String')
    .overload('java.lang.String', 'java.security.Provider')
    .overload('java.lang.String', 'java.lang.String')
*/
function hookCipherGetInstance() {
    var cipherGetInstance = Java.use('javax.crypto.Cipher')['getInstance'].overload("java.lang.String");
    cipherGetInstance.implementation = function (type) {
        send("[Cipher.getInstance()]: type: " + type);
        var tmp = this.getInstance(type);
        send("[Cipher.getInstance()]:  cipherObj: " + tmp);
        cipherList.push(tmp);
        return tmp;
    }
}


function hookCipherGetInstance2() {
    var cipherGetInstance = Java.use('javax.crypto.Cipher')['getInstance'].overload('java.lang.String', 'java.security.Provider');
    cipherGetInstance.implementation = function (transforamtion, provider) {
        send("[Cipher.getInstance2()]: transforamtion: " + transforamtion + ",  provider: " + provider);
        var tmp = this.getInstance(transforamtion, provider);
        send("[Cipher.getInstance2()]:  cipherObj: " + tmp);
        cipherList.push(tmp);
        return tmp;
    }
}

function hookCipherGetInstance3() {
    var cipherGetInstance = Java.use('javax.crypto.Cipher')['getInstance'].overload('java.lang.String', 'java.lang.String');
    cipherGetInstance.implementation = function (transforamtion, provider) {
        send("[Cipher.getInstance3()]: transforamtion: " + transforamtion + ",  provider: " + provider);
        var tmp = this.getInstance(transforamtion, provider);
        send("[Cipher.getInstance3()]:  cipherObj: " + tmp);
        cipherList.push(tmp);
        return tmp;
    }
}


/*
    .overload('int', 'java.security.cert.Certificate')
    .overload('int', 'java.security.Key')
    .overload('int', 'java.security.Key', 'java.security.AlgorithmParameters')
    //.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec')
    .overload('int', 'java.security.cert.Certificate', 'java.security.SecureRandom')
    .overload('int', 'java.security.Key', 'java.security.SecureRandom')
    .overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom')
    .overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom')
*/
function hookCipherInit() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.cert.Certificate');
    cipherInit.implementation = function (mode, cert) {
        send("[Cipher.init()]: mode: " + decodeMode(mode) + ", cert: " + cert + " , cipherObj: " + this);
        var tmp = this.init(mode, cert);
    }
}

function hookCipherInit2() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key');
    cipherInit.implementation = function (mode, secretKey) {
        send("[Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey);
    }
}

function hookCipherInit3() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.AlgorithmParameters');
    cipherInit.implementation = function (mode, secretKey, alParam) {
        send("[Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " alParam:" + alParam + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, alParam);
    }
}

function hookCipherInit4() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec');
    cipherInit.implementation = function (mode, secretKey, spec) {
        send("[Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " spec:" + spec + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, spec);
    }
}

function hookCipherInit5() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.cert.Certificate', 'java.security.SecureRandom');
    cipherInit.implementation = function (mode, cert, secureRandom) {
        send("[Cipher.init()]: mode: " + decodeMode(mode) + ", cert: " + cert + " secureRandom:" + secureRandom + " , cipherObj: " + this);
        var tmp = this.init(mode, cert, secureRandom);
    }
}

function hookCipherInit6() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.SecureRandom');
    cipherInit.implementation = function (mode, secretKey, secureRandom) {
        send("[Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " secureRandom:" + secureRandom + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, secureRandom);
    }
}

function hookCipherInit7() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom');
    cipherInit.implementation = function (mode, secretKey, spec, secureRandom) {
        send("[Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " spec:" + spec + " secureRandom: " + secureRandom + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, spec, secureRandom);
    }
}

function hookCipherInit8() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom');
    cipherInit.implementation = function (mode, secretKey, alParam, secureRandom) {
        send("[Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " alParam:" + alParam + " secureRandom: " + secureRandom + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, alParam, secureRandom);
    }
}

/*
    .overload()
    .overload('[B')
    .overload('[B', 'int')
    .overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer')
    .overload('[B', 'int', 'int')
    .overload('[B', 'int', 'int', '[B')
    .overload('[B', 'int', 'int', '[B', 'int')
*/

function hookDoFinal() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload();
    cipherInit.implementation = function () {
        send("[Cipher.doFinal()]: " + "  cipherObj: " + this);
        var tmp = this.doFinal();
        dumpByteArray('Result', tmp);
        return tmp;
    }
}

function hookDoFinal2() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B');
    cipherInit.implementation = function (byteArr) {
        send("[Cipher.doFinal2()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer', byteArr);
        var tmp = this.doFinal(byteArr);
        dumpByteArray('Result', tmp);
        return tmp;
    }
}

function hookDoFinal3() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int');
    cipherInit.implementation = function (byteArr, a1) {
        send("[Cipher.doFinal3()]: " + "  cipherObj: " + this);
        dumpByteArray('Out buffer', byteArr);
        var tmp = this.doFinal(byteArr, a1);
        dumpByteArray('Out buffer', byteArr);
        return tmp;
    }
}

function hookDoFinal4() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer');
    cipherInit.implementation = function (a1, a2) {
        send("[Cipher.doFinal4()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer', a1.array());
        var tmp = this.doFinal(a1, a2);
        dumpByteArray('Out buffer', a2.array());
        return tmp;
    }
}

function hookDoFinal5() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int');
    cipherInit.implementation = function (byteArr, a1, a2) {
        send("[Cipher.doFinal5()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer', byteArr);
        var tmp = this.doFinal(byteArr, a1, a2);
        dumpByteArray('Out buffer', tmp);
        return tmp;
    }
}

function hookDoFinal6() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B');
    cipherInit.implementation = function (byteArr, a1, a2, outputArr) {
        send("[Cipher.doFinal6()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer', byteArr);
        var tmp = this.doFinal(byteArr, a1, a2, outputArr);
        dumpByteArray('Out buffer', outputArr);

        return tmp;
    }
}

function hookDoFinal7() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B', 'int');
    cipherInit.implementation = function (byteArr, a1, a2, outputArr, a4) {
        send("[Cipher.doFinal7()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer', byteArr);
        var tmp = this.doFinal(byteArr, a1, a2, outputArr, a4);
        dumpByteArray('Out buffer', outputArr);
        return tmp;
    }
}

/*
    .overload('[B')
    .overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer')
    .overload('[B', 'int', 'int')
    .overload('[B', 'int', 'int', '[B')
    .overload('[B', 'int', 'int', '[B', 'int')
*/
function hookUpdate() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B');
    cipherInit.implementation = function (byteArr) {
        send("[Cipher.update()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer', byteArr);
        var tmp = this.update(byteArr);
        dumpByteArray('Out buffer', tmp);
        return tmp;
    }
}

function hookUpdate2() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer');
    cipherInit.implementation = function (byteArr, outputArr) {
        send("[Cipher.update2()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer', byteArr.array());
        var tmp = this.update(byteArr, outputArr);
        dumpByteArray('Out buffer', outputArr.array());
        return tmp;
    }
}

function hookUpdate3() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int');
    cipherInit.implementation = function (byteArr, a1, a2) {
        send("[Cipher.update3()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer', byteArr);
        var tmp = this.update(byteArr, a1, a2);
        dumpByteArray('Out buffer', tmp);
        return tmp;
    }
}

function hookUpdate4() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B');
    cipherInit.implementation = function (byteArr, a1, a2, outputArr) {
        send("[Cipher.update4()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer', byteArr);
        var tmp = this.update(byteArr, a1, a2, outputArr);
        dumpByteArray('Out buffer', outputArr);
        return tmp;
    }
}

function hookUpdate5() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B', 'int');
    cipherInit.implementation = function (byteArr, a1, a2, outputArr, a4) {
        send("[Cipher.update5()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer', byteArr);
        var tmp = this.update(byteArr, a1, a2, outputArr, a4);
        dumpByteArray('Out buffer', outputArr);
        return tmp;
    }
}

/*
* List Cipher instances collected in cipherList   
*/
function ListCiphers() {
    Java.perform(function () {
        for (var i = 0; i < cipherList.length; i++) {
            send("[" + i + "] " + cipherList[i]);
        }
    });
    return "[done]";
}

/*
* Get Cipher instance from cipherList using it's name e.g. Cipger.toString() (like: Cipher@a0b1c2)   
* Example: GetCipher('Cipher@a0b1c2')
*/
function GetCipher(cipherName) {
    var result = null;
    Java.perform(function () {
        for (var i = 0; i < cipherList.length; i++) {
            if (cipherName.localeCompare("" + cipherList[i]) == 0)
                result = cipherList[i];
        }
    });
    return result;
}

/*
* Call doUpdate on Cipher instance from cipherList using it's name e.g. Cipger.toString() (like: Cipher@a0b1c2), you can pass buffer into it which will be processed.
* The bytes buffer must be Java [B   
* Example: doUpdate('Cipher@a0b1c2', buffer)
*/
function doUpdate(cipherName, bytes) {
    Java.perform(function () {
        var cipher = GetCipher(cipherName);
        cipher.update(bytes);
        //cipher.doFinal();
    });
}

/*
* Call doFinal on Cipher instance from cipherList using it's name e.g. Cipger.toString() (like: Cipher@a0b1c2)
* Example: doFinal('Cipher@a0b1c2')
*/
function doFinal(cipherName) {
    Java.perform(function () {
        var cipher = GetCipher(cipherName);
        cipher.final(bytes);
        //cipher.doFinal();
    });
}

function decodeMode(mode) {
    if (mode == 1)
        return "Encrypt mode";
    else if (mode == 2)
        return "Decrypt mode";
    else if (mode == 3)
        return "Wrap mode";
    else if (mode == 4)
        return "Unwrap mode";
}

/* All below is hexdump implementation*/
function dumpByteArray(title, byteArr) {
    if (byteArr != null) {
        try {
            var buff = new ArrayBuffer(byteArr.length)
            var dtv = new DataView(buff)
            for (var i = 0; i < byteArr.length; i++) {
                dtv.setUint8(i, byteArr[i]); // Frida sucks sometimes and returns different byteArr.length between ArrayBuffer(byteArr.length) and for(..; i < byteArr.length;..). It occured even when Array.copyOf was done to work on copy.
            }
            send(title + ":\n");
            send(hexdumpJS(dtv.buffer, 0, byteArr.length))
        } catch (error) { send("Exception has occured in hexdump") }
    }
    else {
        send("byteArr is null!");
    }
}

function _fillUp(value, count, fillWith) {
    var l = count - value.length;
    var ret = "";
    while (--l > -1)
        ret += fillWith;
    return ret + value;
}
function hexdumpJS(arrayBuffer, offset, length) {

    var view = new DataView(arrayBuffer);
    offset = offset || 0;
    length = length || arrayBuffer.byteLength;

    var out = _fillUp("Offset", 8, " ") + "  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n";
    var row = "";
    for (var i = 0; i < length; i += 16) {
        row += _fillUp(offset.toString(16).toUpperCase(), 8, "0") + "  ";
        var n = Math.min(16, length - offset);
        var string = "";
        for (var j = 0; j < 16; ++j) {
            if (j < n) {
                var value = view.getUint8(offset);
                string += (value >= 32 && value < 128) ? String.fromCharCode(value) : ".";
                row += _fillUp(value.toString(16).toUpperCase(), 2, "0") + " ";
                offset++;
            }
            else {
                row += "   ";
                string += " ";
            }
        }
        row += " " + string + "\n";
    }
    out += row;
    return out;
};
"""