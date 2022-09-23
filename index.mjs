import * as jose from "jose";

const generateEncryptedJwt = (subject, payload, secret) => {
	return new jose.EncryptJWT(payload)
		.setProtectedHeader({ alg: "dir", enc: "A256GCM" })
		.setIssuedAt()
		.setSubject(subject)
		.setIssuer("https://example.com")
		.setAudience("https://example.com/test")
		.setExpirationTime("1d")
		.encrypt(secret);
};

const decryptJwt = async (jwt, secret) => {
	const options = {
		issuer: "https://example.com",
		audience: "https://example.com/test",
		contentEncryptionAlgorithms: ["A256GCM"],
		keyManagementAlgorithms: ["dir"],
	};
	return jose.jwtDecrypt(jwt, secret, options);
};

const signJwt = async (subject, payload, secret) => {
	return new jose.SignJWT(payload)
		.setProtectedHeader({ alg: "HS256" })
		.setSubject(subject)
		.setIssuedAt()
		.setIssuer("https://example.com")
		.setAudience("https://example.com/test")
		.setExpirationTime("1d")
		.sign(secret)
};

const verifyJwt = async (jwt, secret) => {
	return await jose.jwtVerify(jwt, secret, {
		issuer: "https://example.com",
		audience: "https://example.com/test",
		algorithms: ["HS256"],
	});
}

const payload = {"this": "is", "a": "test"};

// 256 bits => 64 characters hex
const secret = Buffer.from("62197fc8886bd3b739dd2cc8aa109d0be93acdea64c07b8908168b80daf1dc47", "hex");

const encryptedJwt = await generateEncryptedJwt("testsub", payload, secret);

const decrypted = await decryptJwt(encryptedJwt, secret);

const signedJwt = await signJwt("testsub", payload, secret);
const verifiedJwt = await verifyJwt(signedJwt, secret);

console.log({payload, secretString: secret.toString("base64"), secret, encryptedJwt, encryptedParts: encryptedJwt.split(".").map((p) => Buffer.from(p, "base64url").toString("utf8")).join("."), decrypted, signedJwt, signedParts: signedJwt.split(".").map((p) => Buffer.from(p, "base64url").toString("utf8")).join("."), verifiedJwt});
