# McAfee Active Response (MAR) Workspace API

This is an example script to pull the McAfee Active Response Workspace API. The script will return a JSON including the threat, affected systems, reputations and trace data of the detection. The output can be used to send the data (e.g. via Syslog) to a SIEM for alerting.

### Requirements:

```
pip install beautifulsoup4 requests
```

### Usage:

```
usage: python3 mar_workspace_api.py -h

McAfee MAR Workspace API

optional arguments:
  -h, --help            show this help message and exit
  --epo_ip EPO_IP, -I EPO_IP
                        McAfee EPO IP/Hostname
  --epo_port EPO_PORT, -P EPO_PORT
                        McAfee EPO Port
  --epo_user EPO_USER, -U EPO_USER
                        McAfee NSM Username
  --epo_pw EPO_PW, -PW EPO_PW
                        McAfee NSM Password
  --hours HOURS, -H HOURS
                        Time to go back in hours
  --loglevel {INFO,DEBUG}, -L {INFO,DEBUG}
                        Loglevel

```

### Example output:

```
{
  "sha256Hash": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
  "sha1Hash": "d452fc7f90813f0c2b549018d71a4c5ed387e898",
  "md5Hash": "37e635a046835c3ba1b68a1f09c47a9d",
  "processSeverity": "s2",
  "processAccumSeverity": "s2",
  "fileName": "sada35.exe",
  "affectedHosts": 1,
  "firstSeen": "2021-02-15T10:49:01Z",
  "prevalence": 1,
  "prevalent": false,
  "lastAction": "2021-02-15T10:49:29Z",
  "behaviorMap": 144,
  "type": "PE",
  "reputations": {
    "results": [
      {
        "gtiReputationLastRefresh": 1616167247783,
        "enterpriseReputationLastRefresh": 1613386124021,
        "comment": null,
        "enterpriseCount": 1,
        "prevalent": false,
        "firstReference": null,
        "productName": null,
        "productVersion": null,
        "company": null,
        "version": null,
        "names": [
          "sada35.exe"
        ],
        "md5": "37E635A046835C3BA1B68A1F09C47A9D",
        "sha256": "23E7FB1DA6C970CE7036B6D7AD7C697F8E476BE6C8FE21FDF6AF731B5906412E",
        "certSha1": "",
        "profilerFlags": "3001a5:0;3002a5:0;3003a5:0;300465:215838;3005a5:20;3006a5:1d703881d617892;300765:1d6bcf54be02b00;300865:d;300965:2;300a65:0;300b65:38;300c65:0;300da5:3;300e65:f46000;300f65:6010;301065:3;301165:17;301265:12;301365:0;301465:1c0000;301565:4001;301665:40;3017a5:10020;3019a5:1000;301a65:3a15fa06001a0003;301b65:be8d00642000be60;301c65:a0d20310a0d2031;3ffea4:0;3fffa8:f148000000320100;",
        "atdReputation": null,
        "atdReputationLastRefresh": null,
        "mwgReputation": null,
        "mwgReputationLastRefresh": null,
        "externalReputation": null,
        "externalReputationLastRefresh": null,
        "certEnterpriseReputation": null,
        "certGtiReputation": null,
        "firstContact": 1613386124021,
        "lastUpdate": 1613386124130,
        "lastAccess": 1613386124021,
        "fileNameCount": 1,
        "filePathCount": 1,
        "filePaths": [
          "C:\\Users\\obfuscated\\Downloads\\sada35.exe"
        ],
        "size": 2185272,
        "signedBits": 0,
        "lastDetectionName": null,
        "detectionCount": 0,
        "localRepLatest": 50,
        "latestRuleId": null,
        "localRepMin": 50,
        "localRepMax": 50,
        "localRepSum": 50,
        "localRepCount": 1,
        "promptRepMin": 0,
        "promptRepMax": 0,
        "promptRepSum": 0,
        "promptRepCount": 0,
        "parentRepMin": 0,
        "parentRepMax": 0,
        "parentRepSum": 0,
        "parentRepCount": 0,
        "goodRepCount": 0,
        "badRepCount": 0,
        "childrenCount": 0,
        "urlRep": {},
        "fileIdentity": null,
        "fileType": 18,
        "compositeReputation": "050|0",
        "priority": 0,
        "fileParents": null,
        "fileRules": null,
        "latestLocalReputationDate": 1613386124130,
        "fileFirstAgentGuid": "{3db83872-3006-11eb-08a7-0050562aa242}",
        "gtiReputation": 0,
        "sha1": "D452FC7F90813F0C2B549018D71A4C5ED387E898",
        "enterpriseReputation": 0
      }
    ]
  },
  "hosts": [
    {
      "guid": "3DB83872-3006-11EB-08A7-0050562AA242",
      "host": "CLIENT1",
      "ip": "10.0.0.5",
      "os": "Windows Server 2016",
      "osVersion": "10.0",
      "status": "ONLINE",
      "firstSeen": 1613386141000,
      "selected": false,
      "processSeverity": "s2",
      "quarantined": false,
      "traces": {
        "events": [
          {
            "traceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "uniqueRuleId": 0,
            "isRoot": 1,
            "parentTraceId": "b19ba0cd-6f78-11eb-8587-aaaaaaaaaaaa",
            "rootTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "parentTraceIdList": [
              "b19ba0cd-6f78-11eb-8589-aaaaaaaaaaaa",
              "b19ba0cd-6f78-11eb-8588-aaaaaaaaaaaa",
              "b19ba0cd-6f78-11eb-8587-aaaaaaaaaaaa"
            ],
            "time": "2021-02-15T10:48:44.101Z",
            "attrBitMask": "0x1",
            "eventType": "Process Created",
            "maGuid": "3DB83872-3006-11EB-08A7-0050562AA242",
            "rootSha2": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
            "processName": "sada35.exe",
            "pid": 7592,
            "cmdLine": "\"C:\\Users\\mcafee\\Downloads\\sada35.exe\" ",
            "user": "mcafee",
            "domainName": "MCAFEEEBC",
            "processReputationSource": "ATP",
            "processReputation": 50,
            "procFileAttrs": {
              "name": "sada35.exe",
              "path": "C:\\Users\\mcafee\\Downloads\\sada35.exe",
              "md5": "37e635a046835c3ba1b68a1f09c47a9d",
              "sha1": "d452fc7f90813f0c2b549018d71a4c5ed387e898",
              "sha256": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
              "size": 2185272,
              "onSystemCreationDate": "2020-12-14T15:23:23.037Z",
              "lastModificationDate": "2021-02-15T10:48:37.408Z",
              "reputationSource": "ATP",
              "reputation": 50
            },
            "dtsType": "shallow",
            "os": "windows",
            "detectionDate": "2021-02-15T10:48:49Z",
            "dtsId": "EDR",
            "tp": "mar_2.4.4.404",
            "version": "2.3"
          },
          {
            "traceId": "669a638d-6f7b-11eb-85a0-aaaaaaaaaaaa",
            "parentTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "rootTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "time": "2021-02-15T10:48:55.805Z",
            "eventType": "Process Reputation Update",
            "maGuid": "3DB83872-3006-11EB-08A7-0050562AA242",
            "processCharacteristics": "0x0",
            "processAccumCharacteristics": "0x0",
            "originalTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "pid": 7592,
            "reputationChangeReason": 0,
            "processName": "sada35.exe",
            "cmdLine": "\"C:\\Users\\mcafee\\Downloads\\sada35.exe\" ",
            "user": "mcafee",
            "domainName": "MCAFEEEBC",
            "processReputationSource": "ATP",
            "processReputation": 50,
            "prevProcessReputation": 50,
            "acquiredProcessReputation": 50,
            "prevAcquiredProcessReputation": 50,
            "procFileAttrs": {
              "name": "sada35.exe",
              "path": "C:\\Users\\mcafee\\Downloads\\sada35.exe",
              "md5": "37e635a046835c3ba1b68a1f09c47a9d",
              "sha1": "d452fc7f90813f0c2b549018d71a4c5ed387e898",
              "sha256": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
              "size": 2185272,
              "onSystemCreationDate": "2020-12-14T15:23:23.037Z",
              "lastModificationDate": "2021-02-15T10:48:37.408Z",
              "reputationSource": "ATP",
              "reputation": 50
            },
            "processSeverity": "s1",
            "processAccumSeverity": "s1",
            "score": 2.25,
            "processAccumScore": 2.25,
            "rootSha2": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
            "dtsType": "shallow",
            "os": "windows",
            "detectionDate": "2021-02-15T10:49:01Z",
            "dtsId": "EDR",
            "tp": "mar_2.4.4.404",
            "version": "2.3"
          },
          {
            "traceId": "669a638d-6f7b-11eb-859f-aaaaaaaaaaaa",
            "uniqueRuleId": 114,
            "ruleVersion": 211,
            "parentTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "rootTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "pid": 7592,
            "time": "2021-02-15T10:48:55.805Z",
            "attrBitMask": "0x1",
            "eventType": "RegValue Modified",
            "maGuid": "3DB83872-3006-11EB-08A7-0050562AA242",
            "behaviorBucketOfEvent": "0x0",
            "rootSha2": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
            "severity": "s1",
            "regKeyName": "HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS",
            "regKeyValueName": "PROXYENABLE",
            "regKeyValueType": "REG_DWORD",
            "KeyValue": "0",
            "KeyOldValue": "0",
            "dtsType": "shallow",
            "os": "windows",
            "detectionDate": "2021-02-15T10:49:01Z",
            "dtsId": "EDR",
            "tp": "mar_2.4.4.404",
            "version": "2.3"
          },
          {
            "traceId": "669a638d-6f7b-11eb-85a3-aaaaaaaaaaaa",
            "parentTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "rootTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "time": "2021-02-15T10:48:55.808Z",
            "eventType": "Process Reputation Update",
            "maGuid": "3DB83872-3006-11EB-08A7-0050562AA242",
            "processCharacteristics": "0x90",
            "processAccumCharacteristics": "0x90",
            "originalTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "pid": 7592,
            "reputationChangeReason": 0,
            "processName": "sada35.exe",
            "cmdLine": "\"C:\\Users\\mcafee\\Downloads\\sada35.exe\" ",
            "user": "mcafee",
            "domainName": "MCAFEEEBC",
            "processReputationSource": "ATP",
            "processReputation": 50,
            "prevProcessReputation": 50,
            "acquiredProcessReputation": 50,
            "prevAcquiredProcessReputation": 50,
            "procFileAttrs": {
              "name": "sada35.exe",
              "path": "C:\\Users\\mcafee\\Downloads\\sada35.exe",
              "md5": "37e635a046835c3ba1b68a1f09c47a9d",
              "sha1": "d452fc7f90813f0c2b549018d71a4c5ed387e898",
              "sha256": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
              "size": 2185272,
              "onSystemCreationDate": "2020-12-14T15:23:23.037Z",
              "lastModificationDate": "2021-02-15T10:48:37.408Z",
              "reputationSource": "ATP",
              "reputation": 50
            },
            "processSeverity": "s2",
            "processAccumSeverity": "s2",
            "score": 20.24,
            "processAccumScore": 20.24,
            "rootSha2": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
            "dtsType": "shallow",
            "os": "windows",
            "detectionDate": "2021-02-15T10:49:01Z",
            "dtsId": "EDR",
            "tp": "mar_2.4.4.404",
            "version": "2.3"
          },
          {
            "traceId": "669a638d-6f7b-11eb-85a2-aaaaaaaaaaaa",
            "uniqueRuleId": 555,
            "ruleVersion": 211,
            "parentTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "rootTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "pid": 7592,
            "time": "2021-02-15T10:48:55.808Z",
            "attrBitMask": "0x1",
            "eventType": "RegValue Deleted",
            "maGuid": "3DB83872-3006-11EB-08A7-0050562AA242",
            "behaviorBucketOfEvent": "0x90",
            "rootSha2": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
            "severity": "s2",
            "regKeyName": "HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS",
            "regKeyValueName": "PROXYSERVER",
            "dtsType": "shallow",
            "os": "windows",
            "detectionDate": "2021-02-15T10:49:01Z",
            "dtsId": "EDR",
            "tp": "mar_2.4.4.404",
            "version": "2.3"
          },
          {
            "traceId": "669a638d-6f7b-11eb-85a1-aaaaaaaaaaaa",
            "uniqueRuleId": 114,
            "ruleVersion": 211,
            "parentTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "rootTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "pid": 7592,
            "time": "2021-02-15T10:48:55.809Z",
            "attrBitMask": "0x1",
            "eventType": "RegValue Deleted",
            "maGuid": "3DB83872-3006-11EB-08A7-0050562AA242",
            "behaviorBucketOfEvent": "0x0",
            "rootSha2": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
            "severity": "s1",
            "regKeyName": "HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS",
            "regKeyValueName": "AUTOCONFIGURL",
            "dtsType": "shallow",
            "os": "windows",
            "detectionDate": "2021-02-15T10:49:01Z",
            "dtsId": "EDR",
            "tp": "mar_2.4.4.404",
            "version": "2.3"
          },
          {
            "traceId": "669a638d-6f7b-11eb-85a4-aaaaaaaaaaaa",
            "uniqueRuleId": 555,
            "ruleVersion": 211,
            "parentTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "rootTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "pid": 7592,
            "time": "2021-02-15T10:48:55.809Z",
            "attrBitMask": "0x1",
            "eventType": "RegValue Deleted",
            "maGuid": "3DB83872-3006-11EB-08A7-0050562AA242",
            "behaviorBucketOfEvent": "0x90",
            "rootSha2": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
            "severity": "s2",
            "regKeyName": "HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS",
            "regKeyValueName": "PROXYOVERRIDE",
            "dtsType": "shallow",
            "os": "windows",
            "detectionDate": "2021-02-15T10:49:01Z",
            "dtsId": "EDR",
            "tp": "mar_2.4.4.404",
            "version": "2.3"
          },
          {
            "traceId": "669a638d-6f7b-11eb-85a5-aaaaaaaaaaaa",
            "uniqueRuleId": 114,
            "ruleVersion": 211,
            "parentTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "rootTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "pid": 7592,
            "time": "2021-02-15T10:48:55.810Z",
            "attrBitMask": "0x1",
            "eventType": "RegValue Deleted",
            "maGuid": "3DB83872-3006-11EB-08A7-0050562AA242",
            "behaviorBucketOfEvent": "0x0",
            "rootSha2": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
            "severity": "s1",
            "regKeyName": "HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS",
            "regKeyValueName": "AUTODETECT",
            "dtsType": "shallow",
            "os": "windows",
            "detectionDate": "2021-02-15T10:49:01Z",
            "dtsId": "EDR",
            "tp": "mar_2.4.4.404",
            "version": "2.3"
          },
          {
            "traceId": "66a18a99-6f7b-11eb-85a5-aaaaaaaaaaaa",
            "uniqueRuleId": 36,
            "ruleVersion": 211,
            "parentTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "rootTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "pid": 7592,
            "time": "2021-02-15T10:48:55.849Z",
            "attrBitMask": "0x1",
            "eventType": "Network Accessed",
            "maGuid": "3DB83872-3006-11EB-08A7-0050562AA242",
            "behaviorBucketOfEvent": "0x0",
            "rootSha2": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
            "severity": "s0",
            "ProcessName": "C:\\Users\\mcafee\\Downloads\\sada35.exe",
            "networkAttributes": {
              "accessType": "CONNECTION_OPENED",
              "Level4Protocol": "TCP",
              "dstIP": "213.124.66.13",
              "dstPort": "80",
              "srcIP": "10.0.0.5",
              "srcPort": "50364",
              "direction": "Outgoing"
            },
            "dtsType": "shallow",
            "os": "windows",
            "detectionDate": "2021-02-15T10:49:01Z",
            "dtsId": "EDR",
            "tp": "mar_2.4.4.404",
            "version": "2.3"
          },
          {
            "traceId": "779e4852-6f7b-11eb-85a5-aaaaaaaaaaaa",
            "uniqueRuleId": 0,
            "parentTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "rootTraceId": "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa",
            "time": "2021-02-15T10:49:24.359Z",
            "attrBitMask": "0x1",
            "eventType": "Process Terminated",
            "maGuid": "3DB83872-3006-11EB-08A7-0050562AA242",
            "rootSha2": "23e7fb1da6c970ce7036b6d7ad7c697f8e476be6c8fe21fdf6af731b5906412e",
            "processName": "sada35.exe",
            "pid": 7592,
            "dtsType": "shallow",
            "os": "windows",
            "detectionDate": "2021-02-15T10:49:29Z",
            "dtsId": "EDR",
            "tp": "mar_2.4.4.404",
            "version": "2.3"
          },
          {
            "traceId": "b19ba0cd-6f78-11eb-8588-aaaaaaaaaaaa",
            "uniqueRuleId": 0,
            "parentTraceId": "b19ba0cd-6f78-11eb-8589-aaaaaaaaaaaa",
            "rootTraceId": "00000000-0000-0000-0000-000000000000",
            "time": "2021-02-15T08:51:41.025Z",
            "attrBitMask": "0x1",
            "eventType": "Process Created",
            "maGuid": "3DB83872-3006-11EB-08A7-0050562AA242",
            "processName": "userinit.exe",
            "pid": 8,
            "cmdLine": "C:\\Windows\\system32\\userinit.exe",
            "user": "mcafee",
            "domainName": "MCAFEEEBC",
            "processReputationSource": "ATP",
            "processReputation": 0,
            "procFileAttrs": {
              "name": "userinit.exe",
              "path": "C:\\Windows\\System32\\userinit.exe",
              "md5": "c1b1ffc800be2f31eb2cf8cb40629c69",
              "sha1": "f1b962cf2939030c15c91226d97b9eeb9649a04a",
              "sha256": "cfc6a18fc8fe7447ecd491345a32f0f10208f114b70a0e9d1cd72f6070d5b36f",
              "size": 33280,
              "onSystemCreationDate": "2016-07-16T13:18:42.004Z",
              "lastModificationDate": "2016-07-16T13:18:42.004Z",
              "reputationSource": "VTP",
              "reputation": 99
            },
            "dtsType": "shallow",
            "os": "windows",
            "detectionDate": "2021-02-15T10:29:38Z",
            "dtsId": "EDR",
            "tp": "mar_2.4.4.404",
            "version": "2.3"
          },
          {
            "traceId": "b19ba0cd-6f78-11eb-8587-aaaaaaaaaaaa",
            "uniqueRuleId": 0,
            "parentTraceId": "b19ba0cd-6f78-11eb-8588-aaaaaaaaaaaa",
            "rootTraceId": "00000000-0000-0000-0000-000000000000",
            "time": "2021-02-15T08:51:41.206Z",
            "attrBitMask": "0x1",
            "eventType": "Process Created",
            "maGuid": "3DB83872-3006-11EB-08A7-0050562AA242",
            "processName": "explorer.exe",
            "pid": 5900,
            "cmdLine": "C:\\Windows\\Explorer.EXE",
            "user": "mcafee",
            "domainName": "MCAFEEEBC",
            "processReputationSource": "ATP",
            "processReputation": 99,
            "procFileAttrs": {
              "name": "explorer.exe",
              "path": "C:\\Windows\\explorer.exe",
              "md5": "044f48aa4b726924881597815a7c1b06",
              "sha1": "2381c7077d48ca9d7a39af7fa39f3d367678cc3a",
              "sha256": "888a2105f62ea40654a1b78de8e76ca1131c16e1d9fd28c75d7f4f3e1c0b8ff5",
              "size": 4673960,
              "onSystemCreationDate": "2020-02-25T18:07:20.571Z",
              "lastModificationDate": "2019-09-11T04:26:27.794Z",
              "reputationSource": "VTP",
              "reputation": 99,
              "Certificates": [
                {
                  "signingCerts": {
                    "IssuerName": "Microsoft Windows Production PCA 2011",
                    "Subject": "Microsoft Windows",
                    "ValidNotBefore": 1556832276000,
                    "ValidNotAfter": 1588454676000,
                    "PublicKeyHash": "adabcb4d16f5d6e833faecdabe19a4e7d1c5bb5a"
                  },
                  "ParentCert": {
                    "IssuerName": "Microsoft Root Certificate Authority 2010",
                    "Subject": "Microsoft Windows Production PCA 2011",
                    "ValidNotBefore": 1319049702000,
                    "ValidNotAfter": 1792435902000,
                    "PublicKeyHash": "a92902398e16c49778cd90f99e4f9ae17c55af53"
                  }
                }
              ]
            },
            "dtsType": "shallow",
            "os": "windows",
            "detectionDate": "2021-02-15T10:29:38Z",
            "dtsId": "EDR",
            "tp": "mar_2.4.4.404",
            "version": "2.3"
          },
          {
            "traceId": "b19ba0cd-6f78-11eb-8589-aaaaaaaaaaaa",
            "uniqueRuleId": 0,
            "parentTraceId": "00000000-0000-0000-0000-000000000000",
            "rootTraceId": "00000000-0000-0000-0000-000000000000",
            "time": "2021-01-28T08:44:40.716Z",
            "attrBitMask": "0x1",
            "eventType": "Process Created",
            "maGuid": "3DB83872-3006-11EB-08A7-0050562AA242",
            "processName": "winlogon.exe",
            "pid": 648,
            "user": "SYSTEM",
            "domainName": "NT AUTHORITY",
            "processReputationSource": "ATP",
            "processReputation": 99,
            "procFileAttrs": {
              "name": "winlogon.exe",
              "path": "C:\\Windows\\System32\\winlogon.exe",
              "md5": "dea4ce12f24601830083126e18a2c7c9",
              "sha1": "39a7038115ad1e578b15dd9fcb7772c1a83a898e",
              "sha256": "f002f8c2ea49d21f242996e3d57f5fdd7995fe6db524bb69bbd7f190cc0211a9",
              "size": 672256,
              "onSystemCreationDate": "2020-02-25T18:07:06.727Z",
              "lastModificationDate": "2019-08-31T01:00:54.417Z",
              "reputationSource": "VTP",
              "reputation": 99
            },
            "dtsType": "shallow",
            "os": "windows",
            "detectionDate": "2021-02-15T10:29:38Z",
            "dtsId": "EDR",
            "tp": "mar_2.4.4.404",
            "version": "2.3"
          }
        ],
        "rootTraceIds": [
          "5fa30768-6f7b-11eb-859f-aaaaaaaaaaaa"
        ],
        "totalEvents": 13
      }
    }
  ]
}
```
