/*
    Axios Supply Chain Attack — YARA Rules
    Advisory: GHSA-fw8c-xr5c-95f9 | MAL-2026-2306
    Source: N3mes1s full RE + dynamic analysis
*/

rule axios_dropper_setup_js {
    meta:
        description = "Axios supply chain - obfuscated setup.js dropper"
        hash = "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09"
        date = "2026-03-31"
    strings:
        $xor = "OrDeR_7077"
        $entry = "_entry"
        $id = "6202033"
    condition:
        filesize < 10KB and $xor and $entry and $id
}

rule axios_win_stage1 {
    meta:
        description = "Axios supply chain - Windows download cradle (system.bat)"
        hash = "f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd"
    strings:
        $cradle = "scriptblock]::Create"
        $post = "packages.npm.org/product1"
    condition:
        filesize < 500 and $cradle and $post
}

rule axios_win_ps_rat {
    meta:
        description = "Axios supply chain - Windows PowerShell RAT"
        hash = "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101"
    strings:
        $class = "Extension.SubRoutine"
        $var1 = "$rotjni"
        $var2 = "$daolyap"
        $rsp1 = "rsp_peinject"
        $rsp2 = "rsp_runscript"
        $rsp3 = "rsp_rundir"
        $rsp4 = "rsp_kill"
    condition:
        $class or ($var1 and $var2) or (3 of ($rsp*))
}

rule axios_macos_nukesped {
    meta:
        description = "Axios supply chain - macOS NukeSped RAT"
        hash = "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a"
    strings:
        $mz = { CA FE BA BE }
        $build = "Jain_DEV"
        $project = "macWebT"
        $drop = "/private/tmp/.%s"
        $codesign = "codesign --force --deep --sign"
        $rsp1 = "rsp_peinject"
        $rsp2 = "rsp_runscript"
    condition:
        $mz at 0 and ($build or $project or ($drop and $codesign) or ($rsp1 and $rsp2))
}

rule axios_linux_python_rat {
    meta:
        description = "Axios supply chain - Linux Python RAT (ld.py)"
        hash = "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf"
    strings:
        $fn1 = "do_action_ijt"
        $fn2 = "do_action_scpt"
        $fn3 = "do_action_dir"
        $rsp1 = "rsp_peinject"
        $rsp2 = "rsp_runscript"
        $rsp3 = "rsp_rundir"
    condition:
        ($fn1 and $fn2 and $fn3) or (3 of ($rsp*))
}

rule axios_rat_generic {
    meta:
        description = "Generic detection for any axios supply chain RAT variant"
    strings:
        $ua = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)"
        $b1 = "FirstInfo"
        $b2 = "BaseInfo"
        $b3 = "CmdResult"
        $r1 = "rsp_peinject"
        $r2 = "rsp_runscript"
        $r3 = "rsp_rundir"
    condition:
        ($ua and 2 of ($b*)) or (3 of ($r*))
}

rule axios_c2_indicators {
    meta:
        description = "Axios supply chain C2 network indicators in files"
    strings:
        $c2 = "sfrclak.com"
        $path = "/6202033"
        $p0 = "packages.npm.org/product0"
        $p1 = "packages.npm.org/product1"
        $p2 = "packages.npm.org/product2"
    condition:
        $c2 or ($path and any of ($p*)) or (2 of ($p*))
}

rule axios_injector_dll {
    meta:
        description = "Extension.SubRoutine .NET injection DLL used by axios RAT"
    strings:
        $mz = { 4D 5A }
        $class = "Extension.SubRoutine" wide
        $method = "Run2" wide
    condition:
        $mz at 0 and $class and $method
}
