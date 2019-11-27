var _ = require("../../lib/underscore")
var bufferValueOf = Buffer.prototype.valueOf

describe("Underscore", function() {
	describe("deepEquals", function() {
		beforeEach(function() { delete Buffer.prototype.valueOf })
		afterEach(function() { Buffer.prototype.valueOf = bufferValueOf })

		describe("given Array", function() {
			it("must return true if equal", function() {
				_.deepEquals([1, 2, 3], [1, 2, 3]).must.be.true()
			})

			it("must return false if not equal", function() {
				_.deepEquals([1, 2, 3], [2, 1, 3]).must.be.false()
			})
		})

		describe("given Buffer", function() {
			it("must return true if equal", function() {
				_.deepEquals(Buffer.from("Hello"), Buffer.from("Hello")).must.be.true()
			})

			it("must return true if nested and equal", function() {
				_.deepEquals({
					buffer: Buffer.from("Hello"),
				}, {
					buffer: Buffer.from("Hello")
				}).must.be.true()
			})

			it("must return false if not equal", function() {
				_.deepEquals(Buffer.from("Hello"), Buffer.from("Yello")).must.be.false()
			})

			it("must return false if nested and not equal", function() {
				_.deepEquals({
					buffer: Buffer.from("Hello"),
				}, {
					buffer: Buffer.from("Yello")
				}).must.be.false()
			})
		})
	})
})
