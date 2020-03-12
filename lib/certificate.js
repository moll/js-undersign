var _ = require("./underscore")
var Bn = require("bn.js")
var Pem = require("./pem")
var X509Asn = require("./x509_asn")
var Crypto = require("crypto")
var LdapAttributes = require("./ldap_attributes")
var flatten = Function.apply.bind(Array.prototype.concat, Array.prototype)
var OCSP_URL_OID = require("./x509_asn").OCSP_URL
// https://tools.ietf.org/html/rfc4517#appendix-A
var EMPTY_ARR = Array.prototype
var LDAP_ATTRS = require("./ldap_attributes.json")
exports = module.exports = Certificate

var rfc4514Attrs = new LdapAttributes(_.pick(LDAP_ATTRS, [
  "0.9.2342.19200300.100.1.1", // userId
  "0.9.2342.19200300.100.1.25", // domainComponent
  "2.5.4.3", // commonName
  "2.5.4.6", // countryName
  "2.5.4.7", // localityName
  "2.5.4.8", // stateOrProvinceName
  "2.5.4.9", // streetAddress
  "2.5.4.10", // organizationName
  "2.5.4.11", // organizationalUnitName
]))

var SIGNATURE_HASH_ALGORITHMS = {
	"rsa-sha1": "sha1",
	"rsa-sha224": "sha224",
	"rsa-sha256": "sha256",
	"rsa-sha384": "sha384",
	"rsa-sha512": "sha512",
	"ecdsa-sha1": "sha1",
	"ecdsa-sha224": "sha224",
	"ecdsa-sha256": "sha256",
	"ecdsa-sha384": "sha384",
	"ecdsa-sha512": "sha512"
}

function Certificate(der) {
	this.asn = X509Asn.Certificate.decode(der)
}

Certificate.prototype.__defineGetter__("serialNumber", function() {
	return this.asn.tbsCertificate.serialNumber
})

Certificate.prototype.__defineGetter__("subject", function() {
	return serializeSubject(this.asn.tbsCertificate.subject)
})

Certificate.prototype.__defineGetter__("subjectDer", function() {
	return X509Asn.Name.encode(this.asn.tbsCertificate.subject)
})

Certificate.prototype.__defineGetter__("validFrom", function() {
	return parseTime(this.asn.tbsCertificate.validity.notBefore)
})

Certificate.prototype.__defineGetter__("validUntil", function() {
	return parseTime(this.asn.tbsCertificate.validity.notAfter)
})

Certificate.prototype.__defineGetter__("subjectDistinguishedName", function() {
	return serializeDistinguishedName(this.asn.tbsCertificate.subject)
})

Certificate.prototype.__defineGetter__("subjectRfc4514Name", function() {
	return serializeRfc4514Name(this.asn.tbsCertificate.subject)
})

Certificate.prototype.__defineGetter__("publicKey", function() {
	return this.asn.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.data
})

Certificate.prototype.__defineGetter__("publicKeyAlgorithm", function() {
	var oid = this.asn.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm
	return oid.join(".")
})

Certificate.prototype.__defineGetter__("publicKeyAlgorithmName", function() {
	return X509Asn.CRYPTO_NAMES[this.publicKeyAlgorithm]
})

Certificate.prototype.__defineGetter__("publicKeyParameters", function() {
	var algorithm = this.asn.tbsCertificate.subjectPublicKeyInfo.algorithm

	switch (this.publicKeyAlgorithmName) {
		case "ecdsa": return X509Asn.EcParameters.decode(algorithm.parameters)
		default: return null
	}
})

Certificate.prototype.__defineGetter__("issuer", function() {
	return serializeSubject(this.asn.tbsCertificate.issuer)
})

Certificate.prototype.__defineGetter__("issuerDer", function() {
	return X509Asn.Name.encode(this.asn.tbsCertificate.issuer)
})

Certificate.prototype.__defineGetter__("issuerDistinguishedName", function() {
	return serializeDistinguishedName(this.asn.tbsCertificate.issuer)
})

Certificate.prototype.__defineGetter__("issuerRfc4514Name", function() {
	return serializeRfc4514Name(this.asn.tbsCertificate.issuer)
})

Certificate.prototype.__defineGetter__("issuerSignatureAlgorithm", function() {
	return this.asn.signatureAlgorithm.algorithm.join(".")
})

Certificate.prototype.__defineGetter__("issuerSignatureAlgorithmName",
	function() {
	return X509Asn.SIGNATURE_NAMES[this.issuerSignatureAlgorithm]
})

Certificate.prototype.__defineGetter__("ocspUrl", function() {
	// Authority Information Access is defined in RFC 5280.
	// https://tools.ietf.org/html/rfc5280#section-4.2.2.1
	var extensions = this.asn.tbsCertificate.extensions || EMPTY_ARR

	var info = extensions.find((e) => e.extnID == "authorityInformationAccess")
	if (info == null) return null

	var ocspInfo = info.extnValue.find((info) => (
		_.deepEquals(info.accessMethod, OCSP_URL_OID) &&
		info.accessLocation.type == "uniformResourceIdentifier"
	))

	return ocspInfo && ocspInfo.accessLocation.value
})

Certificate.prototype.hasSigned = function(signable, signature) {
	var algorithm = this.publicKeyAlgorithmName
	var verifier = Crypto.createVerify("sha256").update(signable)

	// "ESTEID-SK 2007" issued certificates sign with RSA.
	// "EID-SK 2011" issued certificates sign with RSA.
	// "ESTEID-SK 2011" issued certificates for Id-card sign with RSA.
	// "ESTEID-SK 2011" issued certificates for Mobile-Id sign with ECDSA.
	// "ESTEID-SK 2015" issued certificates sign with both RSA and ECDSA.
	// "ESTEID2018" issued certificates sign with ECDSA.
	switch (algorithm) {
		case "rsa": break
		case "ecdsa":
			// https://www.openssl.org/docs/man1.1.0/man3/ECDSA_sign.html
			var r = new Bn(signature.slice(0, signature.length / 2))
			var s = new Bn(signature.slice(signature.length / 2))
			signature = X509Asn.EcSignature.encode({r: r, s: s})
			break
			
		default: throw new Error("Unsupported signature algorithm: " + algorithm)
	}

	// OpenSSL v1.0's PEM_read_bio_PUBKEY() fails if a PEM line happens to be
	// a multiple of 253 — e.g. 1012 characters or 2024 characters in base64.
	// https://github.com/openssl/openssl/issues/9187
	return verifier.verify(breakLines(80, this.toString("pem")), signature)
}

Certificate.prototype.hasIssued = function(cert) {
	// "ESTEID-SK 2007" issued with RSA-SHA1.
	// "ESTEID-SK 2011" issued with RSA-SHA1.
	// "ESTEID-SK 2011" from ~2015 issued with RSA-SHA256.
	// "EID-SK 2011" issued with RSA-SHA1.
	// "EID-SK 2011" from ~2015 issued with RSA-SHA256.
	// "ESTEID-SK 2015" issued with RSA-SHA256
	// "ESTEID2018" issued with ECDSA-SHA256
	var algoName = cert.issuerSignatureAlgorithmName
	var hashName = SIGNATURE_HASH_ALGORITHMS[algoName]
	if (!hashName) throw new Error("Unsupported signature algorithm: " + algoName)

	// tbsCertificate.signature MUST contain the same algorithm identifier as the
	// signatureAlgorithm field in the sequence Certificate.
	// https://tools.ietf.org/html/rfc5280#section-4.1.2.3
	if (!_.deepEquals(
		cert.asn.tbsCertificate.signature,
		cert.asn.signatureAlgorithm
	)) return false

	// DER support in verification arrived in Node v11.6. Before that PEM only.
	var der = X509Asn.TBSCertificate.encode(cert.asn.tbsCertificate)
	var verifier = Crypto.createVerify(hashName).update(der)
	var pem = breakLines(80, this.toString("pem"))
	return verifier.verify(pem, cert.asn.signature.data)
}

Certificate.prototype.toBuffer = function() {
	return X509Asn.Certificate.encode(this.asn)
}

Certificate.prototype.toString = function(fmt) {
	switch (fmt) {
		case "hex":
		case "base64": return this.toBuffer().toString(fmt)
		case "pem": return Pem.serialize("CERTIFICATE", this.toBuffer())
		default: throw new RangeError("Unsupported format: " + fmt)
	}
}

exports.parse = function(derOrPem) {
	var der = Pem.isPem(derOrPem) ? Pem.parse(derOrPem) : derOrPem
	return new Certificate(der)
}

function serializeSubject(seq) {
	return seq.value.map((names) => names.reduce(function(obj, name) {
		var oid = name.type, value = name.value

		if (LdapAttributes.has(oid))
			obj[LdapAttributes.get(oid).name] = LdapAttributes.parse(oid, value)
		else
			obj[oid.join(".")] = value

		return obj
		}, {})
	)
}

function serializeDistinguishedName(seq) {
	return seq.value.map((names) => names.map(function(name) {
		var oid = name.type, value = name.value

		return LdapAttributes.has(oid)
			? LdapAttributes.serializeKv(oid, LdapAttributes.parse(oid, value))
			: LdapAttributes.serializeUnknownKv(oid, value)
		}).join("+")
	)
}

function serializeRfc4514Name(seq) {
	return seq.value.map((names) => names.map(function(name) {
		var oid = name.type, value = name.value

		return rfc4514Attrs.has(oid)
			? rfc4514Attrs.serializeKv(oid, LdapAttributes.parse(oid, value))
			: LdapAttributes.serializeUnknownKv(oid, value)
	}).join("+")).join(",")
}

function parseTime(obj) {
	switch (obj.type) {
		case "utcTime":
		case "genTime": return new Date(obj.value)
		default: throw new RangeError("Invalid time type: " + obj.type)
	}
}

function breakLines(length, text) {
	var wrapped = new RegExp(`(.{1,${length}})`, "g")
	var lines = flatten(text.split("\n").map((line) => line.match(wrapped) || ""))
	return lines.join("\n")
}
