var cacertblock = {
	// SHA-1 fingerprints of certs reported owned by CNNIC
	sha1 : [
		'8B:AF:4C:9B:1D:F0:2A:92:F7:DA:12:8E:B9:1B:AC:F4:98:60:4B:6F', // CNNIC Root
		'99:A6:9B:E6:1A:FE:88:6B:4D:2B:82:00:7C:B8:54:FC:31:7E:15:39', // Entrust Secure Server CA (37:4A:D2:43)
		'68:56:BB:1A:6C:4F:76:DA:CA:36:21:87:CC:2C:CD:48:4E:DD:C2:5D', // CNNIC SSL (under Entrust.net)
		'AA:CA:FB:20:21:98:0A:D5:7E:55:32:1E:DC:90:41:A2:F1:B3:16:54' // Unknown, from centalert by chihchun
	],
	onLoad: function() {

		//var found = [];

		const Cc = Components.classes;
		const Ci = Components.interfaces;

		var caTreeView = Cc["@mozilla.org/security/nsCertTree;1"].createInstance(Ci.nsICertTree);
		var aConsoleService = Cc["@mozilla.org/consoleservice;1"].getService(Ci.nsIConsoleService);

		//ref: http://mxr.mozilla.org/mozilla-central/source/security/manager/pki/resources/content/certManager.js
		caTreeView.loadCerts(Ci.nsIX509Cert.CA_CERT);

		// Go through entire db, looking for CNNIC certs and delete them.
		// Note that deleteEntryObject() would not actually delete the built-in ones, 
		// but run it would effectly disable it's usage.

		for (var i=1; i<caTreeView.rowCount; i++) {
			if (caTreeView.isContainer(i)) continue;
			var cert = caTreeView.getCert(i);

			/* for (i in this.sha1) {
				found[i] = false;
			} */

			for (j in this.sha1) {
				if (cert.sha1Fingerprint === this.sha1[j]) {
					aConsoleService.logStringMessage("CNNIC CA Cert Block: Found cert '" + cert.commonName + "' and attempt to delete or disabled it.\nThis message may show up next time for built-in CA certs since they cannot be deleted but only disabled.");
					caTreeView.deleteEntryObject(i);
					
					//ref: http://mxr.mozilla.org/mozilla-central/source/security/manager/pki/resources/content/editcerts.js
					/* var o1 = {}, o2 = {}, o3 = {};
					cert.getUsagesArray(false, o1, o2, o3);
					if (o1.value !== cert.USAGE_NOT_ALLOWED) {
						certdb.setCertTrust(cert, Ci.nsIX509Cert.CA_CERT, 0);
					} */
					//found[j] = true;
				}
			}
		}

		// Step 2: find the known certs that is not in the db, install them but not set for usage.

		// Extracted from exported .crt files.
		// ref: http://felixcat.net/2010/01/throw-out-cnnic/
		/*
		const certs = [
			null,
			null,
			'MIIEFzCCA4CgAwIBAgIEQoeioDANBgkqhkiG9w0BAQUFADCBwzELMAkGA1UEBhMCVVMxFDASBgNVBAoTC0VudHJ1c3QubmV0MTswOQYDVQQLEzJ3d3cuZW50cnVzdC5uZXQvQ1BTIGluY29ycC4gYnkgcmVmLiAobGltaXRzIGxpYWIuKTElMCMGA1UECxMcKGMpIDE5OTkgRW50cnVzdC5uZXQgTGltaXRlZDE6MDgGA1UEAxMxRW50cnVzdC5uZXQgU2VjdXJlIFNlcnZlciBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNzA1MTExNDAzMjJaFw0xMjAzMDEwNTAwMDBaMDUxCzAJBgNVBAYTAkNOMRIwEAYDVQQKEwlDTk5JQyBTU0wxEjAQBgNVBAMTCUNOTklDIFNTTDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJi/7qMONmdodRqKb5QMZM8XaQLXy26EjTnBblL+WC1yPGXxTFyYSjrJKB3iUKP1Inj9dymNfQqD0F0p/aWh6RClHb/NoAwR2zjIf8xrStVOeUCieuDz5l7TVKZ/aklW/UcIzImj9SjRzixzJ0Qdd7L0SW11WgzUd/IEqHHy2DHq3qJC3qUnfkWLmmPlE7QUJ4cg62kFwZ2vznHb9tlwGEPd2ik4iACBUL8X17x4BV//DeOl1z75DpDMLjmUTi/vwmsc/1Ko9ElwrfkjF4L7XY/hbQ/N/qmhMMn8OBiIwbTI14oRS/8eiUqTe0L0KwrC+Yo96HBTBRObAZWgV/X0ZxkCAwEAAaOCAR8wggEbMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZW50cnVzdC5uZXQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbnRydXN0Lm5ldC9zZXJ2ZXIxLmNybDARBgNVHSAECjAIMAYGBFUdIAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFPAXYhNVPbP/CgBr+1CEl/PtYtAaMB0GA1UdDgQWBBRL1eFRFqKn7aOlx+D/sYcYDsDj1TAZBgkqhkiG9n0HQQAEDDAKGwRWNy4xAwIAgTANBgkqhkiG9w0BAQUFAAOBgQBE8Wd1YSChOVKq/nmol4vS1BFliayedJBiTW9EfeyCtfPvCb9mRjpT2+k4P2y9xJSFOB7Z9FsvcjMwqUWdf9qDMWqm4QXddxlztDtZ6PZiSvZ3H+mXiWa/mCLLmFhoTElB/XYY4aqg/smxWaVJzHcbcP0ED5PeCxQiFpgbHeRVig=='
		];

		var certdb = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);


		for (j in this.sha1) {
			if (!found[j]) {
				alert(j + ' not found');
				if (certs[j]) {
					// ref: https://developer.mozilla.org/en/Code_snippets/Miscellaneous#Adding_custom_certificates_to_a_XULRunner_application
					alert(certs[j]);
					//won't work?
					//http://www.mozilla.org/projects/security/pki/nss/tools/certutil.html#1034193
					certdb.addCertFromBase64(certs[j], ",,", "");
				}
			}
		}
		*/
	}
};
window.addEventListener("load", function (e) { cacertblock.onLoad(e) }, false);
