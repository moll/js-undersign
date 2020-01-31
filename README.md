Undersign.js
============
[![NPM version][npm-badge]](https://www.npmjs.com/package/undersign)
[![Build status][travis-badge]](https://travis-ci.org/moll/js-undersign)

Undersign.js is a **command line utility** and **JavaScript library** for creating **eIDAS** compatible **XAdES digital signatures** and **ASiC-E containers** with the accompanying **[OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) responses** ([RFC 2560][rfc2560]) and **timestamps** ([RFC 3161][rfc3161]). It's got built-in support for the Estonian Id-card, Mobile-Id, Smart-Id services and their related [BDOC specification](https://www.sk.ee/repository/bdoc-spec21.pdf), but is otherwise useful for generic XAdES signatures. It uses the [Euroopean Trusted List](https://webgate.ec.europa.eu/tl-browser) XML format as the source for certificate authorities.

Note that currently Undersign.js is in a **beta** and **request for comments** phase. Please give it a try and report back on its correctness and API design.

[npm-badge]: https://img.shields.io/npm/v/undersign.svg
[travis-badge]: https://travis-ci.org/moll/js-undersign.svg?branch=master
[rfc2560]: https://tools.ietf.org/html/rfc2560
[rfc3161]: https://tools.ietf.org/html/rfc3161
[digidoc-client]: https://github.com/open-eid/DigiDoc4-Client
[ria]: https://ria.ee


Installing
----------
```sh
npm install undersign
```

Undersign.js follows [semantic versioning](http://semver.org), so feel free to depend on its major version with something like `>= 1.0.0 < 2` (a.k.a `^1.0.0`).

As said above, please note that Undersign.js is currently in a **request for comments** phase. Expect API breakage between minor versions until v1.

### Installing the Command Line Utility
Undersign.js comes with a command line utility named `hades`. NPM usually installs executables automatically either to the local path `./node_modules/.bin/hades` or, if you installed Undersign.js globally with `npm install --global undersign`, to `/usr/local/bin/hades`.

While the API of the library shall follow semantic versioning religiously, the command line utility is mostly for debugging and interactive use. As such, it's commands and options may change even between minor versions (from v1.3 to v1.4, for example). Still, [CHANGELOG](./CHANGELOG.md) will cover those changes, too. If you're intending to automate the use of Undersign.js, I suggest doing so via the library interface.


Using the Library
-----------------
Creating digital signatures is a multi-step process. Undersign.js comes with a coordinator named "Hades" that stores some of the configuration and has functions for easier use. It's also the main export of Undersign.js:

```javascript
var Hades = require("undersign")
```

Create a new instance of `Hades` with certificates from a trust service list you've acquired separately, and a timemark or a timestamp service URL. For more information, see either the section below on [Trusted Lists](#trusted-lists) or for OCSP, timestamp and timemark service URLs, the section on [Trust Services](#trust-services).

```javascript
var Fs = require("fs")
var Tsl = require("undersign/lib/tsl")

var hades = new Hades({
  certificates: Tsl.parse(Fs.readFileSync("./tsl/ee.xml")).certificates,
  timemarkUrl: "…",
  timestampUrl: "…"
})
```

Pass the country (e.g. Estonian) trusted list's certificates to `Hades` as that's where the service providers and certificate issuers are listed in. The European trusted list itself just contains links to regional lists and Undersign.js doesn't do any recursion on your behalf.

`Tsl.prototype.certificates` gives you back a `Certificates` instance. If you want to do signing with only a subset of issuers, you could populate a new `Certificates` instance yourself with certificates from multiple TSL.

#### Signing
To start the signing process, create a new `Xades` document with the certificate of the signer and files to be signed. We'll talk how to get the certificate later.

```javascript
var Xades = require("undersign/xades")
var Crypto = require("crypto")
var Certificate = require("undersign/lib/certificate")
var certificate = Certificate.parse(Fs.readFileSync("./mary.pem"))
var document = Fs.readFileSync("./document.txt")

var xades = hades.new(certificate, [{
  path: "document.txt",
  type: "text/plain",
  hash: Crypto.createHash("sha256").update(document).digest()
}])

xades instanceof Xades // => true
```

Note that instead of the file contents, you're really giving only file paths, their MIME types and SHA256 hashes to `Xades`. This way you can precompute the hash if you're signing the same file over and over. The MIME type is part of the signature, so if you're later going to create an ASiC-E container (.asice or .bdoc file), use the same MIME type there. The reason a MIME type is signed seems to be legal, to be explicit that you're signing one interpretation of a stream of bytes as opposed to another. I probably never comes up in practice, but theoretically the same bytes could be two file formats with different presentations at the same time.

Once you've got a `Xades` document, you can get the signable XML with `xades.signable` or the SHA256 hash directly via `xades.signableHash`. The former will be a string, the latter a Node.js `Buffer` object. We'll talk about how to sign that hash in more detail later, but for now, image you'll be passing that to the Id-card somehow and get back a signature. Then, pass that signature to the `Xades` document.

```javascript
xades.setSignature(signThroughMagic(xades.signableHash))
```

Almost done. For the signature to have legal value in Europe, you'll also need to **check the signer's certificate validity** and **timestamp the signature**. There are two methods to do so — regular timestamping or timemarking.

#### Timestamping and OCSP
For a regular timestamp, you've got two operations ahead of you — a certificate validity request ([OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol)) and a timestamp request.

The order of the two operations is in my opinion unclearly specified in the [XAdES Baseline Profile](https://www.etsi.org/deliver/etsi_ts/103100_103199/103171/02.01.01_60/ts_103171v020101p.pdf) specification. It only states that signatures that want to conform to XAdES LT (long-term timestamped signatures) should first conform to XAdES T (timestamped signatures). From that, the Estonian [Information System Authority][ria] has [induced](https://github.com/open-eid/libdigidocpp/issues/323) that the timestamp _must_ be made prior to the OCSP request. For compatibility with their [Digidoc][digidoc-client] software, it's best to follow their position.

While the OCSP server is often available in the certificate, the timestamping server needs explicit configuration via `timestampUrl` before using `Hades.prototype.timestamp`:

```javascript
var hades = new Hades({timestampUrl: "…"})
var xades = …
xades.setTimestamp(await hades.timestamp(xades))
```

Legally, any timestamp server that returns responses signed by a certificate that's in the European Trusted List will suffice. See the section on [Timestamp Services](#timestamp-services) for a few examples.

Finally, use `Hades.prototype.ocsp` to do the certificate validity request. As OCSP needs access to the certificate's issuer certificate, `Hades` will try to get the from the certificates you configured before. If it fails to do so, you'll see an error.

```javascript
xades.setOcspResponse(hades.ocsp(certificate))
```

The OCSP server is taken from the certificate itself as these servers are generally publicly available. That's the case with the Estonian citizen certificates from 2018. If you want to use another OCSP server or a proxy, you can pass that to `Hades` via `ocspUrl`:

```javascript
var hades = new Hades({ocspUrl: "…"})
```

Unfortunately Estonian citizen certificates issued before 2018 by SK ID Solutions AS's ESTEID-SK 2011 and ESTEID-SK 2015 certificates lack OCSP URLs. Through testing it turned out they're providing a publicly available OCSP server for those at <http://aia.sk.ee/esteid2011> and <http://aia.sk.ee/esteid2015> respectively, but it's unclear how they're intended to be discovered. Some say the public accessibility of the newer ESTEID 2018 certificates' OCSP servers only arose thanks to a new eIDAS requirement. I also heard a rumor about wishes to continue to charge Estonians for our identity certificate OCSP servers while making them publicly accessible to other member states, but since Estonians would've merely routed their requests through other countries, it was fortunately decided to make all publicly available.

#### Timemarking
Timemarking utilizes the certificate validity ([OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol)) request to also get a timestamp for the signature. However, **the OCSP server and its service provider you're using needs to support this explicitly**. It's not evident technically which OCSP servers do and which don't, as the process piggybacks on the regular _nonce_ of the OCSP request and is more a legal property than a technical one. It relies on the OCSP server provider being able to provide timestamping proof later when asked. While the signature should have legal standing regardless, it's useful to set the signature's policy to the [BDOC specification](https://www.sk.ee/repository/bdoc-spec21.pdf). This way other applications (such as the [Estonian Digidoc][digidoc-client]) can identify the use of timemarks and check their validity automatically.

The Estonian [SK ID Solutions AS](https://www.sk.ee) provides such a timemark-compatible OCSP server at <http://ocsp.sk.ee> for at worst [€0.1 per request](https://www.skidsolutions.eu/teenused/hinnakiri/kehtivuskinnituse-teenus).

To utilize that, set the `timemarkUrl` when creating an instance of `Hades`:

```javascript
var hades = new Hades({
  tsl: Tsl.parse(Fs.readFileSync("./tsl/ee.xml")).certificates,
  timemarkUrl: "http://ocsp.sk.ee"
})
```

Don't forget setting the policy to `bdoc` when creating a new XAdES signature for timemarking:

```javascript
var xades = hades.new(certificate, files, {policy: "bdoc"})
```

Then, instead of a regular OCSP request, use `Hades.prototype.timemark` to get both a OCSP response and a timemark in one call:

```javascript
xades.setOcspResponse(await hades.timemark(xades))
```

The reason you've got to set the signature policy (BDOC in the above example) before signing or timemarking is that the policy reference also gets signed.

#### Signature Export
With the OCSP and timestamp added, you've got a valid XAdES signature. To get the `<asic:XAdESSignatures>` XML representing the signature, use `Xades.prototype.toString` or pass `xades` to `String`:

```javascript
xades.toString() == String(xades)
```

If you plan to have multiple people sign the same document, redo the steps from `Hades.new`, storing each resulting signature XML separately. Then, when it's time to export the signatures to an ASiC-E container (ZIP file with specific files) for compatibility with existing digital signature software (like the [Estonian Digidoc][digidoc-client]), use the `Asic` object:

```javascript
var Fs = require("fs")

var asic = new Asic
asic.pipe(Fs.createWriteStream("document.asice"))
asic.addSignature(xades)
asic.add("document.txt", "Hello, World!", "text/plain")
asic.end()
```

Be sure to use the same document path and MIME type as you did when creating the signature. To add multiple signatures, just call `Asic.prototype.addSignature` for each.

The `Asic` object has a Node.js stream-like interface, hence the use of `pipe` above. This saves `Asic` from buffering the contents of the entire ZIP file. You can also call `Asic.prototype.toStream` to get the output stream directly for further manipulation.

Streaming is especially useful in a web server context, where you can pipe the ASiC-E container to the client as you're creating it.

```javascript
var Http = require("http")

Http.createServer(function(req, res) {
  var asic = new Asic
  res.setHeader("Content-Type", asic.type)
  asic.pipe(res)

  asic.addSignatures(…)
  asic.add(…)
  asic.end()
}).listen(3000)
```

`Asic.prototype.type` gets you the MIME type of the ASiC-E container ("application/vnd.etsi.asic-e+zip"`).

### Trusted Lists
The eIDAS digital signature infrastructure depends on [trusted lists](https://ec.europa.eu/digital-single-market/en/eu-trusted-lists-trust-service-providers), which are XML documents describing which service providers and certificate authorities (CAs) are authorized to hand out certificates to citizens and later confirm their signatures with timestamps.

Undersign.js doesn't at the moment download the European or national trusted lists automatically, so to sign documents with it, you'll need to obtain those manually and possibly verify them with external tools. The [Makefile](./Makefile) in Undersign.js's repository has a simple example Make target for downloading the trusted lists. Alternatively, get the XML files from the URLs below.

You can use the `hades` command line tool with `hades tsl <tsl-file>` to peek into the trusted lists. If you pass it the European Trusted List, you can find out where to download the other region and country lists.

#### Production Trusted Lists
- [European Trusted List XML](https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml)
- [Estonian Trusted List XML](https://sr.riik.ee/tsl/estonian-tsl.xml)

#### Testing Trusted Lists
- [European Trusted List XML](https://open-eid.github.io/test-TL/tl-mp-test-EE.xml) with its [certificate](https://open-eid.github.io/test-TL/trusted-test-tsl.crt).
- [Estonian Trusted List XML](https://open-eid.github.io/test-TL/EE_T.xml)

### Trust Services
To create legally valid signatures in Europe, you'll need access to some of the trust services listed in the European Trusted Lists. Unfortunately, not all essential services are free, causing digital signing in Europe to be rather costly endeavour, especially for non-personal or collective use. Mozilla's Lets Encrypt managed to liberate web certificates and make it free for everyone. Hopefully someday we'll have a similar revolution in the European digital signatures ecosystem. Until then, here are a few services you'll come across.

#### Certificate Validity (OCSP)
Generally, OCSP servers are expected to be freely accessible and their URLs embedded in certificates. That seems to be the case with Estonian citizen certificates, however, as alluded to before, I've seen Mobile-Id certificates from 2015 that lack OCSP URLs. How to obtain valid OCSP server URLs for such certificates is yet unsolved.

Neither do I know what the situation is with Lithuanian citizen certificates. Do they embed OCSP URLs in certificates and are those servers publicly accessible?

#### Timestamp Services
Timestamping is one of the services not freely available that you'll need for eIDAS compatible digital signatures.

If you're in Estonia and plan to create digital signatures for **personal use**, the [Information System Authority][ria] provides a [free timestamping proxy]((https://www.id.ee/index.php?id=39021)) at <http://dd-at.ria.ee/tsa> with a limit of 2000 timestamps per month per IP address.

[SK ID Solutions AS](https://www.sk.ee) sells a [timestamping service](https://www.skidsolutions.eu/teenused/ajatempliteenus/) for approximately €0.036 per request as of Nov 27, 2019.

As any timestamp service in the European Trusted List will suffice for eIDAS compatible signatures, you may find cheaper options by browsing the [European Trusted List](https://webgate.ec.europa.eu/tl-browser). Please let me know at [andri@dot.ee][email] if you do find some.

[SK ID Solutions AS](https://www.sk.ee) also has a timestamping server for testing at <http://demo.sk.ee/tsa> which, being in the Estonian Test Trusted List, can be used during development.

#### Timemarking Services
Alternatively, you may obtain a timestamp together with the certificate validity (OCSP) response. I currently know of only a single service provider supporting this, the Estonian [SK ID Solutions AS](https://www.sk.ee). They provide <http://ocsp.sk.ee> for at worst [€0.1 per request](https://www.skidsolutions.eu/teenused/hinnakiri/kehtivuskinnituse-teenus). I'm not sure if that OCSP+timestamp service is applicable if you're creating signatures with certificates not originally issued in Estonia or by them. If possible, use a plain timestamp server to timestamp your signatures.

[SK ID Solutions AS](https://www.sk.ee) also has a timarking OCSP server for testing at <http://demo.sk.ee/ocsp> which, being in the Estonian Test Trusted List, can be used during development.

### Mobile-Id Test Accounts
To test Mobile-Id signing, use one of the Mobile-Id test phone numbers:

Phone        | Personal id | Name
-------------|-------------|-----
+37200000766 | 60001019906 | Estonian Mary
+37200000566 | 60001018800 | Estonian Mary (PNOEE-certificate)
+37060000666 | 50001018865 | Lithuanian Mary (PNOLT-certificate)

For more info and test numbers, see the [SK ID Solutions wiki][mobile-id-test]. You can also [register your own phone number](https://demo.sk.ee/MIDCertsReg/index.php) for use in the demo environment.

[mobile-id-test]: https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO


Using the Command Line
----------------------
Undersign.js comes with an command line executable for interactive use, such as testing or signing a few documents of your own. Refer to the [Installing](#installing) section on where to find the `hades` executable.

If you run `hades` with the `--help` option, you'll see a list of available commands:

```
Usage: hades [options] [<command> [<args>...]]

Options:
    -h, --help             Display this help and exit.
    -V, --version          Display version and exit.

Commands:
    asic                   Create an ASiC-E file.
    certificate            Print information on certificate.
    ocsp                   Check certificate validity via OCSP.
    ts                     Query the timestamp server.
    tsl                    Get the European Trust Service List.
    mobile-id-certificate  Get the certificate associated with a phone number.
    mobile-id-sign         Sign a file with Mobile-Id.
    smart-id-certificate   Get the certificate associated with a person.
    smart-id-sign          Sign a file with Smart-Id.
    validate               Validates the signature XML created by Undersign.

For more help or to give feedback, please contact andri@dot.ee.
```

You can run each of the commands in turn with `--help` to see more detailed options:

```
$ hades mobile-id-sign --help
```

I'll add more elaborate documentation in the future, but for now, here are a few use cases.

### Get the Certificate of a Mobile-Id User
Use `hades mobile-id-certificate`:
```
$ hades mobile-id-certificate --mobile-id-user example.com --mobile-id-password 00000000-1337-1337-4242-000000000000 +3721234567 38706180338
```

Note that because Mobile-Id is a paid service, you'll have to authenticate with `--mobile-id-user` and `--mobile-id-password`.

To use the public Mobile-Id test environment, leave out the user and password options. For example, to get Mary's certificate:
```
$ hades mobile-id-certificate +37200000766 60001019906
```

### Sign with Mobile-Id
Use `hades mobile-id-sign`:
```
hades mobile-id-sign --tsl ./tsl/ee.xml --timestamp --timestamp-url http://dd-at.ria.ee/tsa --mobile-id-user example.com --mobile-id-password 00000000-1337-1337-4242-000000000000 --phone +3721234567 --id 38706180338 document.txt
```

This will print out the resulting `<asic:XAdESSignatures>` XML.

To use the public Mobile-Id test environment, leave out the user and password options and switch the trusted list to its test variant. For example, to sign with Mary's certificate:
```
hades mobile-id-sign --tsl ./tsl/ee_test.xml --timestamp --timestamp-url http://demo.sk.ee/tsa --phone +37200000766 --id 60001019906 document.txt
```

If you've [registered your own phone number](https://demo.sk.ee/MIDCertsReg/index.php) to the Mobile-Id test environment, you can actually create legitimate digital signatures by timestamping the signature with a production timestamp server instead of the demo server. For example, an Estonian using the [Information System Authority][ria]'s timestamp proxy for **personal use** would look something like:
```
hades mobile-id-sign --tsl ./tsl/ee.xml --timestamp --timestamp-url http://dd-at.ria.ee/tsa --phone +3721234567 --id 38706180338 document.txt
```

### Create ASiC-E Container
You can combine the signature XML with the original document to create a `document.asice` container:
```
hades asic -o document.asice signature.xml document.txt
```

Hades supports reading from standard input directly, so you can replace `signature.xml` with `-` and pipe the sign command. In the public Mobile-Id test environment, that would look like:
```
hades mobile-id-sign --tsl ./tsl/ee_test.xml --timestamp --timestamp-url http://demo.sk.ee/ocsp --phone +37200000766 --id 60001019906 document.txt | hades asic -o mary.asice - document.txt
```


License
-------
Undersign.js is released under a *Lesser GNU Affero General Public License*, which in summary means:

- You **can** use this program for **no cost**.
- You **can** use this program for **both personal and commercial reasons**.
- You **do not have to share your own program's code** which uses this program.
- You **have to share modifications** (e.g. bug-fixes) you've made to this program.

For more convoluted language, see the `LICENSE` file.


About
-----
**[Andri Möll][moll]** typed this and the code.  
**[SA Eesti Koostöö Kogu][kogu]** sponsored the majority of engineering work in the context of [Rahvaalgatus][rahvaalgatus], a public initiatives site.

If you find Undersign.js needs improving, please don't hesitate to type to me now at [andri@dot.ee][email] or [create an issue online][issues].

[email]: mailto:andri@dot.ee
[issues]: https://github.com/moll/js-undersign/issues
[moll]: https://m811.com
[kogu]: https://www.kogu.ee
[rahvaalgatus]: https://rahvaalgatus.ee
