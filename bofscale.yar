rule BOFScale_Tailscaled_BOFPE {
    meta:
        description = "Detects tailscaled BOF-PE - modified Tailscale daemon running in-memory via C2"
        author = "NetSPI"
        severity = "critical"
        reference = "https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/"

    strings:
        // "tailscaled shutdown gracefully"
        $s1 = { 74 61 69 6C 73 63 61 6C 65 64 20 73 68 75 74 64 6F 77 6E 20 67 72 61 63 65 66 75 6C 6C 79 }

        // "No socket provided, using random socket"
        $s2 = { 4E 6F 20 73 6F 63 6B 65 74 20 70 72 6F 76 69 64 65 64 2C 20 75 73 69 6E 67 20 72 61 6E 64 6F 6D 20 73 6F 63 6B 65 74 }

        // "beaconWriter" - Go type redirecting stdout to Beacon API
        $s3 = { 62 65 61 63 6F 6E 57 72 69 74 65 72 }

        // "TS_DEBUG_DERP_WS_CLIENT" - forces WebSocket DERP relay
        $s4 = { 54 53 5F 44 45 42 55 47 5F 44 45 52 50 5F 57 53 5F 43 4C 49 45 4E 54 }

        // "program.exe" - fake argv[0] placeholder
        $s5 = { 70 72 6F 67 72 61 6D 2E 65 78 65 }

        // "-tun=userspace-networking"
        $s6 = { 2D 74 75 6E 3D 75 73 65 72 73 70 61 63 65 2D 6E 65 74 77 6F 72 6B 69 6E 67 }

        // "-no-logs-no-support"
        $s7 = { 2D 6E 6F 2D 6C 6F 67 73 2D 6E 6F 2D 73 75 70 70 6F 72 74 }

        // "BeaconOutput" - CGO import for C2 output
        $b1 = { 42 65 61 63 6F 6E 4F 75 74 70 75 74 }

        // "BeaconDataParse" - BOF data parsing
        $b2 = { 42 65 61 63 6F 6E 44 61 74 61 50 61 72 73 65 }

        // "BeaconDataExtract" - BOF argument extraction
        $b3 = { 42 65 61 63 6F 6E 44 61 74 61 45 78 74 72 61 63 74 }

        // "-state" + "mem:" co-occurrence (in-memory state, no disk)
        $s8 = { 2D 73 74 61 74 65 }
        $s9 = { 6D 65 6D 3A }

    condition:
        // Must have BOF-PE specific tailscaled indicators (not present in legitimate tailscaled)
        ($s1 or $s2 or $s3) and
        // Plus at least one Beacon API reference
        (1 of ($b*)) and
        // Plus at least two operational indicators
        (2 of ($s4, $s5, $s6, $s7, $s8, $s9))
}


rule BOFScale_Tailscale_Client_BOFPE {
    meta:
        description = "Detects tailscale client BOF-PE - C++ client controlling tailscaled daemon over named pipe"
        author = "NetSPI"
        severity = "critical"
        reference = "https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/"

    strings:
        // "tailscale IPR pipe, is tailscaled async BOF running"
        $s1 = { 74 61 69 6C 73 63 61 6C 65 20 49 50 52 20 70 69 70 65 2C 20 69 73 20 74 61 69 6C 73 63 61 6C 65 64 20 61 73 79 6E 63 20 42 4F 46 20 72 75 6E 6E 69 6E 67 }

        // "status from backed" - distinctive typo fingerprint
        $s2 = { 73 74 61 74 75 73 20 66 72 6F 6D 20 62 61 63 6B 65 64 }

        // "No headscale login-server provided"
        $s3 = { 4E 6F 20 68 65 61 64 73 63 61 6C 65 20 6C 6F 67 69 6E 2D 73 65 72 76 65 72 20 70 72 6F 76 69 64 65 64 }

        // "Host: local-tailscaled.sock"
        $s4 = { 48 6F 73 74 3A 20 6C 6F 63 61 6C 2D 74 61 69 6C 73 63 61 6C 65 64 2E 73 6F 63 6B }

        // "Tailscale-Cap: 125"
        $s5 = { 54 61 69 6C 73 63 61 6C 65 2D 43 61 70 3A 20 31 32 35 }

        // "WantRunningSet" - local API prefs mask
        $s6 = { 57 61 6E 74 52 75 6E 6E 69 6E 67 53 65 74 }

        // "AdvertiseRoutesSet"
        $s7 = { 41 64 76 65 72 74 69 73 65 52 6F 75 74 65 73 53 65 74 }

        // "No socket provided, bailing"
        $s8 = { 4E 6F 20 73 6F 63 6B 65 74 20 70 72 6F 76 69 64 65 64 2C 20 62 61 69 6C 69 6E 67 }

        // "igoring" - distinctive misspelling of "ignoring"
        $s9 = { 69 67 6F 72 69 6E 67 }

        // "Fetched latest status"
        $s10 = { 46 65 74 63 68 65 64 20 6C 61 74 65 73 74 20 73 74 61 74 75 73 }

        // "NotepadURLs" - internal pref key
        $s11 = { 4E 6F 74 65 70 61 64 55 52 4C 73 }

        // "FrontendLogID" - startup JSON field
        $s12 = { 46 72 6F 6E 74 65 6E 64 4C 6F 67 49 44 }

        // "zzzzzzzzzzz" - BEACON_MAIN format string (11 z's)
        $b1 = { 7A 7A 7A 7A 7A 7A 7A 7A 7A 7A 7A }

        // "__declspec(dllexport) void go" - BOF-PE entry point export
        $b2 = { 42 65 61 63 6F 6E 44 61 74 61 50 61 72 73 65 }

    condition:
        // Any of the highly unique strings is an immediate match
        ($s1 or $s2 or $s3) or
        // Or a combination of protocol + API indicators
        ($s4 and $s5 and 2 of ($s6, $s7, $s8, $s9, $s10, $s11, $s12)) or
        // Or BEACON_MAIN format string + BeaconDataParse with protocol indicators
        ($b1 and $b2 and 1 of ($s4, $s5, $s6, $s7))
}


rule BOFScale_SocksPortFwd_BOFPE {
    meta:
        description = "Detects socksportfwd BOF-PE - async SOCKS5 port forwarder for C2 implant"
        author = "NetSPI"
        severity = "high"
        reference = "https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/"

    strings:
        // "features to stop the task" - unique substring of the shutdown hint printf
        $s1 = { 66 65 61 74 75 72 65 73 20 74 6F 20 73 74 6F 70 20 74 68 65 20 74 61 73 6B }

        // "This BOF only supports execution via the async API"
        $s2 = { 54 68 69 73 20 42 4F 46 20 6F 6E 6C 79 20 73 75 70 70 6F 72 74 73 20 65 78 65 63 75 74 69 6F 6E 20 76 69 61 20 74 68 65 20 61 73 79 6E 63 20 41 50 49 }

        // "stop event from beacon API"
        $s3 = { 73 74 6F 70 20 65 76 65 6E 74 20 66 72 6F 6D 20 62 65 61 63 6F 6E 20 41 50 49 }

        // "Port forwarder listening on %s:%d"
        $s4 = { 50 6F 72 74 20 66 6F 72 77 61 72 64 65 72 20 6C 69 73 74 65 6E 69 6E 67 20 6F 6E 20 25 73 3A 25 64 }

        // "Forwarding to %s:%d via SOCKS5 proxy %s:%d"
        $s5 = { 46 6F 72 77 61 72 64 69 6E 67 20 74 6F 20 25 73 3A 25 64 20 76 69 61 20 53 4F 43 4B 53 35 20 70 72 6F 78 79 20 25 73 3A 25 64 }

        // "igoring" - distinctive misspelling shared with the tailscale client BOF
        $s6 = { 69 67 6F 72 69 6E 67 }

        // "SOCKS5 connection established to target"
        $s7 = { 53 4F 43 4B 53 35 20 63 6F 6E 6E 65 63 74 69 6F 6E 20 65 73 74 61 62 6C 69 73 68 65 64 20 74 6F 20 74 61 72 67 65 74 }

        // "Shutdown event signaled"
        $s8 = { 53 68 75 74 64 6F 77 6E 20 65 76 65 6E 74 20 73 69 67 6E 61 6C 65 64 }

        // "BeaconGetStopJobEvent" - async BOF API
        $b1 = { 42 65 61 63 6F 6E 47 65 74 53 74 6F 70 4A 6F 62 45 76 65 6E 74 }

        // "--t and --tp are mandatory"
        $s9 = { 2D 2D 74 20 61 6E 64 20 2D 2D 74 70 20 61 72 65 20 6D 61 6E 64 61 74 6F 72 79 }

        // "zzzzzzzzzzzz" - BEACON_MAIN format string (12 z's)
        $b2 = { 7A 7A 7A 7A 7A 7A 7A 7A 7A 7A 7A 7A }

    condition:
        // Any of the three most distinctive strings
        (1 of ($s1, $s2, $s3)) or
        // Or a combination of SOCKS5 port forwarding + BOF indicators
        ($b1 and 2 of ($s4, $s5, $s6, $s7, $s8, $s9)) or
        // Or BEACON_MAIN format string + async BOF API with port forwarding
        ($b2 and $b1 and 1 of ($s4, $s5))
}


rule BOFScale_Generic_BOFPE {
    meta:
        description = "Generic detection for any BOFScale component running in memory"
        author = "NetSPI"
        severity = "high"
        reference = "https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/"

    strings:
        // "async BOF" - referenced across components
        $s1 = { 61 73 79 6E 63 20 42 4F 46 }

        // "igoring" - distinctive typo in both tailscale and socksportfwd BOFs
        $s2 = { 69 67 6F 72 69 6E 67 }

        // "BeaconDataParse"
        $b1 = { 42 65 61 63 6F 6E 44 61 74 61 50 61 72 73 65 }

        // "BeaconDataExtract"
        $b2 = { 42 65 61 63 6F 6E 44 61 74 61 45 78 74 72 61 63 74 }

        // "BeaconPrintf"
        $b3 = { 42 65 61 63 6F 6E 50 72 69 6E 74 66 }

        // "BeaconOutput"
        $b4 = { 42 65 61 63 6F 6E 4F 75 74 70 75 74 }

        // "BeaconGetStopJobEvent"
        $b5 = { 42 65 61 63 6F 6E 47 65 74 53 74 6F 70 4A 6F 62 45 76 65 6E 74 }

        // "beaconWriter"
        $b6 = { 62 65 61 63 6F 6E 57 72 69 74 65 72 }

        // "local-tailscaled.sock"
        $t1 = { 6C 6F 63 61 6C 2D 74 61 69 6C 73 63 61 6C 65 64 2E 73 6F 63 6B }

        // "tailscaled shutdown gracefully"
        $t2 = { 74 61 69 6C 73 63 61 6C 65 64 20 73 68 75 74 64 6F 77 6E 20 67 72 61 63 65 66 75 6C 6C 79 }

        // "features to stop the task" - unique substring of the socksportfwd shutdown hint
        $t3 = { 66 65 61 74 75 72 65 73 20 74 6F 20 73 74 6F 70 20 74 68 65 20 74 61 73 6B }

        // "headscale login-server"
        $t4 = { 68 65 61 64 73 63 61 6C 65 20 6C 6F 67 69 6E 2D 73 65 72 76 65 72 }

    condition:
        // Beacon API usage combined with tailscale/BOF-PE operational strings
        (2 of ($b*)) and (1 of ($s*) or 1 of ($t*))
}
