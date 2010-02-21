var cacertblock = {
	// SHA-1 fingerprints of certs reported owned by CNNIC
	sha1 : [
		'8B:AF:4C:9B:1D:F0:2A:92:F7:DA:12:8E:B9:1B:AC:F4:98:60:4B:6F', // CNNIC Root
		'99:A6:9B:E6:1A:FE:88:6B:4D:2B:82:00:7C:B8:54:FC:31:7E:15:39', // Entrust Secure Server CA (37:4A:D2:43)
		'68:56:BB:1A:6C:4F:76:DA:CA:36:21:87:CC:2C:CD:48:4E:DD:C2:5D', // CNNIC SSL (under Entrust.net)
		'AA:CA:FB:20:21:98:0A:D5:7E:55:32:1E:DC:90:41:A2:F1:B3:16:54' // Unknown, from centalert by chihchun
	],
	onLoad: function() {

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

			for (j in this.sha1) {
				if (cert.sha1Fingerprint === this.sha1[j]) {
					aConsoleService.logStringMessage("CNNIC CA Cert Block: Found cert '" + cert.commonName + "' and attempt to delete or disabled it.\nThis message may show up next time for built-in CA certs since they cannot be deleted but only disabled.");
					caTreeView.deleteEntryObject(i);
				}
			}
		}
	}
};
window.addEventListener("load", function (e) { cacertblock.onLoad(e) }, false);
