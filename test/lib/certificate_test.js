var _ = require("../../lib/underscore")
var Fs = require("fs")
var Asn = require("../../lib/asn")
var X509Asn = require("../../lib/x509_asn")
var Crypto = require("crypto")
var Certificate = require("../../lib/certificate")
var LdapAttributes = require("../../lib/ldap_attributes")
var Pem = require("../../lib/pem")
var demand = require("must")
var OCSP_URL_OID = require("../../lib/x509_asn").OCSP_URL
var EMPTY_ARR = Array.prototype
var EMPTY_BUFFER = Buffer.alloc(0)
var GENERATE_KEYS = !!Crypto.generateKeyPairSync
var HASH_ALGORITHMS = ["sha1", "sha224", "sha256", "sha384", "sha512"]
var NO_PARAMS = Buffer.from("0500", "hex")
var nextSerialNumber = Math.floor(10000 * Math.random())

describe("Certificate", function() {
	describe(".prototype.serialNumber", function() {
		it("must return the serial number", function() {
			var cert = new Certificate(newCertificate({serialNumber: 42}))
			cert.serialNumber.toNumber().must.eql(42)
		})
	})

	function mustHaveSubject(prop) {
		it("must serialize name with multiple relative parts", function() {
			var cert = new Certificate(newCertificate({
				[prop]: [
					{countryName: "EE"},
					{organizationName: "AS Foo"},
					{organizationalUnitName: "Bars", localityName: "Tallinn"}
				]
			}))

			cert[prop].must.eql([
				{countryName: "EE"},
				{organizationName: "AS Foo"},
				{organizationalUnitName: "Bars", localityName: "Tallinn"}
			])
		})

		it("must serialize unknown attribute as OID", function() {
			var cert = new Certificate(newCertificate({
				[prop]: [
					{countryName: "EE"},
					{"2.5.4.1337": "Hello, world"}
				]
			}))

			cert[prop].must.eql([
				{countryName: "EE"},
				{"2.5.4.1337": encodeUtf8("Hello, world")}
			])
		})
	}

	function mustHaveSubjectRfc4514Name(prop) {
		it("must serialize name with multiple relative parts", function() {
			var cert = new Certificate(newCertificate({
				[prop]: [
					{countryName: "EE"},
					{organizationName: "AS Foo"},
					{organizationalUnitName: "Bars", localityName: "Tallinn"}
				]
			}))

			cert[prop + "Rfc4514Name"].must.equal("C=EE,O=AS Foo,OU=Bars+L=Tallinn")
		})

		_.each({
			userId: "UID",
			domainComponent: "DC",
			commonName: "CN",
			countryName: "C",
			localityName: "L",
			stateOrProvinceName: "ST",
			streetAddress: "STREET",
			organizationName: "O",
			organizationalUnitName: "OU",
		}, function(shortName, name) {
			it(`must serialize ${name} as string`, function() {
				var cert = new Certificate(newCertificate({[prop]: [{[name]: "foo"}]}))
				cert[prop + "Rfc4514Name"].must.equal(`${shortName}=foo`)
			})
		})

		it("must serialize givenName as DirectoryString in hex", function() {
			var cert = new Certificate(newCertificate({
				[prop]: [{givenName: "John Smith"}]
			}))

			var oid = LdapAttributes.get("givenName").oid

			var value = Asn.DirectoryString.encode({
				type: "utf8String",
				value: "John Smith"
			})

			var dn = `${oid.join(".")}=#${value.toString("hex")}`
			cert[prop + "Rfc4514Name"].must.equal(dn)
		})

		it("must serialize emailAddress as Ia5String in hex", function() {
			var cert = new Certificate(newCertificate({
				[prop]: [{emailAddress: "user@example.com"}]
			}))

			var oid = LdapAttributes.get("emailAddress").oid
			var value = Asn.Ia5String.encode("user@example.com")
			var dn = `${oid.join(".")}=#${value.toString("hex")}`
			cert[prop + "Rfc4514Name"].must.equal(dn)
		})
	}

	describe(".prototype.subject", function() {
		mustHaveSubject("subject")
	})

	describe(".prototype.subjectRfc4514Name", function() {
		mustHaveSubjectRfc4514Name("subject")
	})

	describe(".prototype.issuer", function() {
		mustHaveSubject("issuer")
	})

	describe(".prototype.issuerRfc4514Name", function() {
		mustHaveSubjectRfc4514Name("issuer")
	})

	function mustHaveValidity(prop) {
		it("must parse utcTime", function() {
			var cert = new Certificate(newCertificate({
				[prop]: {type: "utcTime", value: Date.UTC(2015, 5, 18, 13, 37, 42)}
			}))

			cert[prop].must.eql(new Date(Date.UTC(2015, 5, 18, 13, 37, 42)))
		})

		it("must parse genTime", function() {
			var cert = new Certificate(newCertificate({
				[prop]: {type: "genTime", value: Date.UTC(2015, 5, 18, 13, 37, 42)}
			}))

			cert[prop].must.eql(new Date(Date.UTC(2015, 5, 18, 13, 37, 42)))
		})
	}

	describe(".prototype.validFrom", function() {
		mustHaveValidity("validFrom")
	})

	describe(".prototype.validUntil", function() {
		mustHaveValidity("validUntil")
	})

	describe(".prototype.ocspUrl", function() {
		it("must return null if no OCSP URL extension", function() {
			var cert = new Certificate(newCertificate())
			demand(cert.ocspUrl).be.null()
		})

		it("must return OCSP URL", function() {
			var cert = new Certificate(newCertificate({
				extensions: [{
					extnID: "authorityInformationAccess",
					extnValue: [{
						accessMethod: OCSP_URL_OID,
						accessLocation: {
							type: "uniformResourceIdentifier",
							value: "http://example.com/ocsp"
						}
					}]
				}]
			}))

			cert.ocspUrl.must.equal("http://example.com/ocsp")
		})
	})

	describe(".prototype.hasSigned", function() {
		describe("given an RSA certificate", function() {
			beforeEach(function() {
				this.rsa = GENERATE_KEYS
					? Crypto.generateKeyPairSync("rsa", {
						modulusLength: 2048,
						privateKeyEncoding: {type: "pkcs8", format: "pem"},
						publicKeyEncoding: {type: "spki", format: "der"}
					})
					: readKeyPairSync(
						__dirname + "/../fixtures/rsa.key",
						__dirname + "/../fixtures/rsa.pub"
					)

				this.certificate = new Certificate(newCertificate({
					publicKey: X509Asn.SubjectPublicKeyInfo.decode(this.rsa.publicKey)
				}))
			})

			it("return true for the correct signature", function() {
				var signable = "Hello, world"
				var signer = Crypto.createSign("sha256")
				var signature = signer.update(signable).sign(this.rsa.privateKey)
				this.certificate.hasSigned(signable, signature).must.be.true()
			})

			it("must return false for the wrong signature", function() {
				var signable = "Hello, world"
				var signer = Crypto.createSign("sha256")
				var signature = signer.update(signable).sign(this.rsa.privateKey)
				signature[10] = ~signature[10]
				this.certificate.hasSigned(signable, signature).must.be.false()
			})
		})

		describe("given a ECDSA signature", function() {
			beforeEach(function() {
				this.ec = GENERATE_KEYS
					? Crypto.generateKeyPairSync("ec", {
						namedCurve: "prime256v1",
						privateKeyEncoding: {type: "pkcs8", format: "pem"},
						publicKeyEncoding: {type: "spki", format: "der"}
					})
					: readKeyPairSync(
						__dirname + "/../fixtures/ecdsa.key",
						__dirname + "/../fixtures/ecdsa.pub"
					)

				this.certificate = new Certificate(newCertificate({
					publicKey: X509Asn.SubjectPublicKeyInfo.decode(this.ec.publicKey)
				}))
			})

			it("must return true for the correct signature", function() {
				var signable = "Hello, world"
				var signer = Crypto.createSign("sha256")
				var signatureDer = signer.update(signable).sign(this.ec.privateKey)
				var signatureAsn = X509Asn.EcSignature.decode(signatureDer)

				this.certificate.hasSigned(signable, Buffer.concat([
					signatureAsn.r.toBuffer("be", 32),
					signatureAsn.s.toBuffer("be", 32)
				])).must.be.true()
			})

			it("must return false for the wrong signature", function() {
				var signable = "Hello, world"
				var signer = Crypto.createSign("sha256")
				var signatureDer = signer.update(signable).sign(this.ec.privateKey)
				var signatureAsn = X509Asn.EcSignature.decode(signatureDer)

				var signature = Buffer.concat([
					signatureAsn.r.toBuffer("be", 32),
					signatureAsn.s.toBuffer("be", 32)
				])

				signature[10] = ~signature[10]
				this.certificate.hasSigned(signable, signature).must.be.false()
			})
		})
	})

	describe(".prototype.hasIssued", function() {
		it("must return false if tbsCertificate.signature algorithm mismatch",
			function() {
			var rsa = GENERATE_KEYS
				? Crypto.generateKeyPairSync("rsa", {
					modulusLength: 2048,
					privateKeyEncoding: {type: "pkcs8", format: "pem"},
					publicKeyEncoding: {type: "spki", format: "der"}
				})
				: readKeyPairSync(
					__dirname + "/../fixtures/rsa.key",
					__dirname + "/../fixtures/rsa.pub"
				)

			var issuer = new Certificate(newCertificate({
				publicKey: X509Asn.SubjectPublicKeyInfo.decode(rsa.publicKey)
			}))

			var unsignedCertificate = newUnsignedCertificate({
				signatureAlgorithm: {
					algorithm: X509Asn.RSA_SHA512,
					parameters: NO_PARAMS
				}
			})

			var der = X509Asn.TBSCertificate.encode(unsignedCertificate)
			var signer = Crypto.createSign("sha256")
			var signature = signer.update(der).sign(rsa.privateKey)

			var certificate = new Certificate(newCertificate({
				certificate: unsignedCertificate,

				signatureAlgorithm: {
					algorithm: X509Asn.RSA_SHA256,
					parameters: NO_PARAMS
				},

				signature: {unused: 0, data: signature}
			}))

			issuer.hasIssued(certificate).must.be.false()
		})

		it("must return false if tbsCertificate.signature parameter mismatch",
			function() {
			var ec = GENERATE_KEYS
				? Crypto.generateKeyPairSync("ec", {
					namedCurve: "prime256v1",
					privateKeyEncoding: {type: "pkcs8", format: "pem"},
					publicKeyEncoding: {type: "spki", format: "der"}
				})
				: readKeyPairSync(
					__dirname + "/../fixtures/ecdsa.key",
					__dirname + "/../fixtures/ecdsa.pub"
				)

			var issuer = new Certificate(newCertificate({
				publicKey: X509Asn.SubjectPublicKeyInfo.decode(ec.publicKey)
			}))

			var unsignedCertificate = newUnsignedCertificate({
				signatureAlgorithm: {
					algorithm: X509Asn.ECDSA_SHA256,

					parameters: X509Asn.EcParameters.encode({
						type: "namedCurve",
						value: "prime192v1"
					})
				}
			})

			var der = X509Asn.TBSCertificate.encode(unsignedCertificate)
			var signer = Crypto.createSign("sha256")
			var signature = signer.update(der).sign(ec.privateKey)

			var certificate = new Certificate(newCertificate({
				certificate: unsignedCertificate,

				signatureAlgorithm: {
					algorithm: X509Asn.ECDSA_SHA256,

					parameters: X509Asn.EcParameters.encode({
						type: "namedCurve",
						value: "prime256v1"
					})
				},

				signature: {unused: 0, data: signature}
			}))

			issuer.hasIssued(certificate).must.be.false()
		})

		describe("given an RSA certificate", function() {
			beforeEach(function() {
				this.rsa = GENERATE_KEYS
					? Crypto.generateKeyPairSync("rsa", {
						modulusLength: 2048,
						privateKeyEncoding: {type: "pkcs8", format: "pem"},
						publicKeyEncoding: {type: "spki", format: "der"}
					})
					: readKeyPairSync(
						__dirname + "/../fixtures/rsa.key",
						__dirname + "/../fixtures/rsa.pub"
					)

				this.issuer = new Certificate(newCertificate({
					publicKey: X509Asn.SubjectPublicKeyInfo.decode(this.rsa.publicKey)
				}))
			})

			HASH_ALGORITHMS.forEach(function(hashName) {
				it(`return true for the correct signature on ${hashName}`, function() {
					var signatureAlgorithm = {
						algorithm: X509Asn.SIGNATURE_OIDS["rsa-" + hashName],
						parameters: NO_PARAMS
					}

					var unsignedCertificate = newUnsignedCertificate({
						signatureAlgorithm: signatureAlgorithm
					})

					var der = X509Asn.TBSCertificate.encode(unsignedCertificate)
					var signer = Crypto.createSign(hashName)
					var signature = signer.update(der).sign(this.rsa.privateKey)

					var certificate = new Certificate(newCertificate({
						certificate: unsignedCertificate,
						signatureAlgorithm: signatureAlgorithm,
						signature: {unused: 0, data: signature}
					}))

					this.issuer.hasIssued(certificate).must.be.true()
				})

				it(`must return false for the wrong signature on ${hashName}`,
					function() {
					var signatureAlgorithm = {
						algorithm: X509Asn.SIGNATURE_OIDS["rsa-" + hashName],
						parameters: NO_PARAMS
					}

					var unsignedCertificate = newUnsignedCertificate({
						signatureAlgorithm: signatureAlgorithm
					})

					var der = X509Asn.TBSCertificate.encode(unsignedCertificate)
					var signer = Crypto.createSign(hashName)
					var signature = signer.update(der).sign(this.rsa.privateKey)
					signature[10] = ~signature[10]

					var certificate = new Certificate(newCertificate({
						certificate: unsignedCertificate,
						signatureAlgorithm: signatureAlgorithm,
						signature: {unused: 0, data: signature}
					}))

					this.issuer.hasIssued(certificate).must.be.false()
				})
			})
		})

		describe("given a ECDSA signature", function() {
			beforeEach(function() {
				this.ec = GENERATE_KEYS
					? Crypto.generateKeyPairSync("ec", {
						namedCurve: "prime256v1",
						privateKeyEncoding: {type: "pkcs8", format: "pem"},
						publicKeyEncoding: {type: "spki", format: "der"}
					})
					: readKeyPairSync(
						__dirname + "/../fixtures/ecdsa.key",
						__dirname + "/../fixtures/ecdsa.pub"
					)

				this.issuer = new Certificate(newCertificate({
					publicKey: X509Asn.SubjectPublicKeyInfo.decode(this.ec.publicKey)
				}))
			})

			HASH_ALGORITHMS.forEach(function(hashName) {
				it(`return true for the correct signature on ${hashName}`, function() {
					var signatureAlgorithm = {
						algorithm: X509Asn.SIGNATURE_OIDS["ecdsa-" + hashName],
						parameters: NO_PARAMS
					}

					var unsignedCertificate = newUnsignedCertificate({
						signatureAlgorithm: signatureAlgorithm
					})

					var der = X509Asn.TBSCertificate.encode(unsignedCertificate)
					var signer = Crypto.createSign(hashName)
					var signature = signer.update(der).sign(this.ec.privateKey)

					var certificate = new Certificate(newCertificate({
						certificate: unsignedCertificate,
						signatureAlgorithm: signatureAlgorithm,
						signature: {unused: 0, data: signature}
					}))

					this.issuer.hasIssued(certificate).must.be.true()
				})

				it(`must return false for the wrong signature on ${hashName}`,
					function() {
					var signatureAlgorithm = {
						algorithm: X509Asn.SIGNATURE_OIDS["ecdsa-" + hashName],
						parameters: NO_PARAMS
					}

					var unsignedCertificate = newUnsignedCertificate({
						signatureAlgorithm: signatureAlgorithm
					})

					var der = X509Asn.TBSCertificate.encode(unsignedCertificate)
					var signer = Crypto.createSign(hashName)
					var signature = signer.update(der).sign(this.ec.privateKey)
					signature[10] = ~signature[10]

					var certificate = new Certificate(newCertificate({
						certificate: unsignedCertificate,
						signatureAlgorithm: signatureAlgorithm,
						signature: {unused: 0, data: signature}
					}))

					this.issuer.hasIssued(certificate).must.be.false()
				})
			})
		})
	})

	describe(".prototype.toBuffer", function() {
		it("must encode back to DER", function() {
			var der = newCertificate()
			new Certificate(der).toBuffer().must.eql(der)
		})
	})
})

function newCertificate(opts) {
	return X509Asn.Certificate.encode({
		tbsCertificate: opts && opts.certificate || newUnsignedCertificate(opts),

		signatureAlgorithm: opts && opts.signatureAlgorithm || {
			algorithm: X509Asn.RSA_SHA256,
			parameters: NO_PARAMS
		},

		signature: opts && opts.signature || {unused: 0, data: EMPTY_BUFFER}
	})
}

function newUnsignedCertificate(opts) {
	var extensions = opts && opts.extensions
	var subject = opts && opts.subject && serializeSubject(opts.subject)
	var issuer = opts && opts.issuer && serializeSubject(opts.issuer)

	var defaultSignatureAlgorithm = {
		algorithm: X509Asn.RSA_SHA256,
		parameters: NO_PARAMS
	}

	return {
		serialNumber: opts && opts.serialNumber || nextSerialNumber++,
		subject: {type: "rdnSequence", value: subject || EMPTY_ARR},
		issuer: {type: "rdnSequence", value: issuer || EMPTY_ARR},

		signature: opts && opts.signatureAlgorithm || defaultSignatureAlgorithm,

		validity: {
			notBefore: opts && opts.validFrom || {type: "utcTime", value: new Date},
			notAfter: opts && opts.validUntil || {type: "utcTime", value: new Date}
		},

		subjectPublicKeyInfo: opts && opts.publicKey || {
			algorithm: defaultSignatureAlgorithm,
			subjectPublicKey: {unused: 0, data: EMPTY_BUFFER}
		},

		extensions: extensions
	}
}

function serializeSubject(relativeNames) {
	return relativeNames.map((names) => _.map(names, function(value, name) {
		if (LdapAttributes.has(name)) return {
			type: LdapAttributes.get(name).oid,
			value: LdapAttributes.serialize(name, value)
		}
		else return {
			type: name.split(/\./g).map(Number),
			value: encodeUtf8(value)
		}
	}))
}

function readKeyPairSync(keyPath, pubPath) {
	return {
		privateKey: Fs.readFileSync(keyPath, "utf8"),
		publicKey: Pem.parse(Fs.readFileSync(pubPath, "utf8"))
	}
}

function encodeUtf8(value) {
	return X509Asn.DirectoryString.encode({type: "utf8String", value: value})
}
