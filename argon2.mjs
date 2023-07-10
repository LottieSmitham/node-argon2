"use strict";
import { deserialize, serialize } from "@phc/format";
import gypBuild from "node-gyp-build";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const { hash: _hash } = gypBuild(fileURLToPath(new URL(".", import.meta.url)));

export const argon2d = 0;
export const argon2i = 1;
export const argon2id = 2;

const types = Object.freeze({ argon2d, argon2i, argon2id });

export const defaults = Object.freeze({
  hashLength: 32,
  saltLength: 16,
  timeCost: 3,
  memoryCost: 1 << 16,
  parallelism: 4,
  type: argon2id,
  version: 0x13,
});

export const limits = Object.freeze({
  hashLength: { min: 4, max: 2 ** 32 - 1 },
  memoryCost: { min: 1 << 10, max: 2 ** 32 - 1 },
  timeCost: { min: 2, max: 2 ** 32 - 1 },
  parallelism: { min: 1, max: 2 ** 24 - 1 },
});

const names = Object.freeze({
  [argon2d]: "argon2d",
  [argon2i]: "argon2i",
  [argon2id]: "argon2id",
});

const bindingsHash = promisify(_hash);
const generateSalt = promisify(randomBytes);

const assertLimits =
  (options) =>
  ([key, { max, min }]) => {
    const value = options[key];

    if (min > value || value > max) {
      throw new Error(`Invalid ${key}, must be between ${min} and ${max}.`);
    }
  };

export const hash = async (plain, { raw, salt, ...options } = {}) => {
  options = { ...defaults, ...options };

  Object.entries(limits).forEach(assertLimits(options));

  salt = salt || (await generateSalt(options.saltLength));

  const hash = await bindingsHash(Buffer.from(plain), salt, options);
  if (raw) {
    return hash;
  }

  const {
    type,
    version,
    memoryCost: m,
    timeCost: t,
    parallelism: p,
    associatedData: data,
  } = options;
  return serialize({
    id: names[type],
    version,
    params: { m, t, p, ...(data ? { data } : {}) },
    salt,
    hash,
  });
};

export const needsRehash = (digest, options) => {
  const { memoryCost, timeCost, version } = { ...defaults, ...options };

  const {
    version: v,
    params: { m, t },
  } = deserialize(digest);
  return +v !== +version || +m !== +memoryCost || +t !== +timeCost;
};

export const verify = async (digest, plain, options) => {
  const obj = deserialize(digest);
  // Only these have the "params" key, so if the password was encoded
  // using any other method, the destructuring throws an error
  if (!(obj.id in types)) {
    return false;
  }

  const {
    id,
    version = 0x10,
    params: { m, t, p, data },
    salt,
    hash,
  } = obj;

  return timingSafeEqual(
    await bindingsHash(Buffer.from(plain), salt, {
      ...options,
      type: types[id],
      version: +version,
      hashLength: hash.length,
      memoryCost: +m,
      timeCost: +t,
      parallelism: +p,
      ...(data ? { associatedData: Buffer.from(data, "base64") } : {}),
    }),
    hash,
  );
};
