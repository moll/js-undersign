var _ = require("./underscore")
var sha1 = require("./crypto").hash.bind(null, "sha1")
module.exports = Certificates

function Certificates(certs) {
	this.bySubjectName = {}
	this.bySubjectHash = {}
	if (certs) certs.forEach(this.add, this)
}

Certificates.prototype.bySubjectName = Object.freeze({})
Certificates.prototype.bySubjectHash = Object.freeze({})

Certificates.prototype.add = function(cert) {
	this.bySubjectName[cert.subjectRfc4514Name] = cert
	this.bySubjectHash[sha1(cert.subjectDer)] = cert
}

Certificates.prototype.has = function(cert) {
	return sha1(cert.subjectDer) in this.bySubjectHash
}

Certificates.prototype.getIssuer = function(cert) {
	var issuer = this.bySubjectHash[sha1(cert.issuerDer)]
	return issuer && issuer.hasIssued(cert) ? issuer : null
}

Certificates.prototype.getBySubjectName = function(name) {
	return this.bySubjectName[name]
}

Certificates.prototype.forEach = function(fn) {
	for (var cert in this.bySubjectHash) fn(this.bySubjectHash[cert])
}

Certificates.prototype.toArray = function() {
	return _.values(this.bySubjectHash)
}

Certificates.prototype.toJSON = Certificates.prototype.toArray
