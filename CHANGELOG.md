## Unreleased
- Removes the `NOT_ACTIVE` Mobile-ID error case as the [SK API removed it on Sep 11, 2020](https://github.com/SK-EID/MID/commit/7dc8b4d7aabeb7765e83879d054d5e535a62a4bf).

- Refactors the Smart-ID session object and exports it for serialization.  
  You can get the Smart-ID session object from `require("undersign/lib/smart_id").SmartIdSession`.

  To serialize a session to a JavaScript object (for storing in the database, for example) call `SmartIdSession.serialize` or `SmartIdSession.prototype.toJSON` on an instance. To parse the returned object back to an instance, call `SmartIdSession.parse`.

- Redesigns the Mobile-ID session use to mirror the `SmartId` API. That is, both `MobileId.prototype.authenticate` and `MobileId.prototype.sign` now return a `MobileIdSession` object you can then pass to `MobileId.prototype.wait`.

  Akin to `SmartIdSession`, you can use `MobileIdSession.serialize` and `MobileIdSession.parse` to save the session somewhere.

- Renames `MobileId.prototype.readCertificate` to `MobileId.prototype.certificate` to match the `SmartId` API.

- Renames `MobileId.confirmation` to `MobileId.verification` to match the name in [SK API documentation][mobile-id-api-verification] and `SmartId.verification`.

- Adds a `MobileIdError` with a code `SESSION_NOT_FOUND` if you `MobileId.prototype.wait` for a session that no longer exists.  
  Sessions expire on SK's side in 5 minutes.

- Adds a `<ds:CanonicalizationMethod>` (XML canonicalization method) element to `<xades:SignatureTimeStamp>`.  
  This permits the [DSS validator][dss-validator] to accept timestamps.

[dss-validator]: https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation
[mobile-id-api-verification]: https://github.com/SK-EID/MID#24-verification-code

## 0.1.337 (Nov 10, 2023)
- Sans three-headed dogs.
