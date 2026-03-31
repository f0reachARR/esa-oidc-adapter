import { generateKeyPairSync } from "node:crypto";

const DEFAULT_MODULUS_LENGTH = 2048;

function parseModulusLength(value) {
	if (value === undefined) {
		return DEFAULT_MODULUS_LENGTH;
	}

	const parsed = Number.parseInt(value, 10);
	if (!Number.isInteger(parsed) || parsed < 2048) {
		throw new Error("modulus length must be an integer >= 2048");
	}

	return parsed;
}

function parseArgs(argv) {
	const args = { modulusLength: DEFAULT_MODULUS_LENGTH };

	for (let index = 0; index < argv.length; index += 1) {
		const value = argv[index];
		if (value === "--") {
			continue;
		}

		if (value === "--modulus-length") {
			args.modulusLength = parseModulusLength(argv[index + 1]);
			index += 1;
			continue;
		}

		if (value === "--help" || value === "-h") {
			args.help = true;
			continue;
		}

		throw new Error(`unknown argument: ${value}`);
	}

	return args;
}

function printHelp() {
	process.stdout.write(`Generate a JSON JWK for OIDC_JWT_PRIVATE_KEY.

Usage:
  pnpm generate:oidc-jwt-key
  pnpm generate:oidc-jwt-key -- --modulus-length 3072

Options:
  --modulus-length <bits>  RSA modulus length, default: 2048
  -h, --help               Show this help
`);
}

function main() {
	const args = parseArgs(process.argv.slice(2));
	if (args.help) {
		printHelp();
		return;
	}

	const { privateKey } = generateKeyPairSync("rsa", {
		modulusLength: args.modulusLength,
		publicExponent: 0x10001,
	});

	const jwk = privateKey.export({ format: "jwk" });
	process.stdout.write(`${JSON.stringify(jwk)}\n`);
}

try {
	main();
} catch (error) {
	process.stderr.write(
		`${error instanceof Error ? error.message : "failed to generate key"}\n`,
	);
	process.exitCode = 1;
}
