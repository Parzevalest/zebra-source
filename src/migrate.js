// migrate.js — ONE-TIME database migration helper.
//
// Copies every document in the SharedKV and PrivateKV collections from the
// CURRENT database (MONGODB_URI) to a NEW database (MONGODB_URI_NEW). It's
// a pure read-from-old / write-to-new copy: it never deletes or modifies
// anything in the old database, so triggering it is safe and repeatable.
//
// This module deliberately does NOT reuse db.js's mongoose connection --
// it opens two brand-new, independent connections (one per database) using
// mongoose.createConnection, so the running app's normal DB access is
// completely unaffected while this runs.
//
// HOW TO USE (see the step-by-step in chat):
//   1. Add env var MONGODB_URI_NEW = <new cluster connection string, with real password>
//   2. Add env var MIGRATION_SECRET = <some long random string you choose>
//   3. Deploy, then visit:  /api/migrate-database?secret=YOUR_MIGRATION_SECRET
//   4. Read the JSON result -- confirm counts match your source counts.
//
// The endpoint is gated behind MIGRATION_SECRET so a random visitor can't
// trigger it. Remove this whole file (and its route) once the migration is
// done and verified.

const mongoose = require("mongoose");

// Same two schemas as db.js -- must match exactly so documents copy cleanly.
const sharedSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  value: { type: String, required: true },
  updated_at: { type: Number, default: Date.now },
});
const privateSchema = new mongoose.Schema({
  owner: { type: String, required: true },
  key: { type: String, required: true },
  value: { type: String, required: true },
  updated_at: { type: Number, default: Date.now },
});

// Copy one collection from source connection to destination connection, in
// batches, using bulk upserts keyed on the same fields db.js treats as
// unique. Upsert (rather than plain insert) means re-running the migration
// is safe -- it just overwrites/refreshes rather than erroring on
// duplicates.
async function copyCollection(SrcModel, DstModel, keyFields) {
  const docs = await SrcModel.find({}).lean();
  let copied = 0;
  const BATCH = 200;
  for (let i = 0; i < docs.length; i += BATCH) {
    const slice = docs.slice(i, i + BATCH);
    const ops = slice.map((d) => {
      const filter = {};
      keyFields.forEach((f) => { filter[f] = d[f]; });
      const doc = Object.assign({}, d);
      delete doc._id; // let the destination assign its own _id
      return { updateOne: { filter, update: { $set: doc }, upsert: true } };
    });
    if (ops.length) {
      await DstModel.bulkWrite(ops, { ordered: false });
      copied += ops.length;
    }
  }
  return { sourceCount: docs.length, copied };
}

async function runMigration() {
  const srcUri = process.env.MONGODB_URI;
  const dstUri = process.env.MONGODB_URI_NEW;
  if (!srcUri) throw new Error("MONGODB_URI (source) is not set");
  if (!dstUri) throw new Error("MONGODB_URI_NEW (destination) is not set");

  // dbName: "test" preserves the same default database name the app already
  // uses (Mongoose defaults to "test" when the URI has no db name in its
  // path -- confirmed from the existing setup). This guarantees the copied
  // data lands in the same place the app will look for it after the switch.
  const srcConn = await mongoose.createConnection(srcUri, { dbName: "test" }).asPromise();
  const dstConn = await mongoose.createConnection(dstUri, { dbName: "test" }).asPromise();

  try {
    const SrcShared = srcConn.model("SharedKV", sharedSchema);
    const DstShared = dstConn.model("SharedKV", sharedSchema);
    const SrcPrivate = srcConn.model("PrivateKV", privateSchema);
    const DstPrivate = dstConn.model("PrivateKV", privateSchema);

    const sharedResult = await copyCollection(SrcShared, DstShared, ["key"]);
    const privateResult = await copyCollection(SrcPrivate, DstPrivate, ["owner", "key"]);

    // Read back the destination counts as an independent verification, so
    // the response proves what actually landed in the new database rather
    // than just what we think we sent.
    const dstSharedCount = await DstShared.countDocuments({});
    const dstPrivateCount = await DstPrivate.countDocuments({});

    return {
      ok: true,
      shared: {
        sourceCount: sharedResult.sourceCount,
        copied: sharedResult.copied,
        destinationCountAfter: dstSharedCount,
      },
      private: {
        sourceCount: privateResult.sourceCount,
        copied: privateResult.copied,
        destinationCountAfter: dstPrivateCount,
      },
      totalSource: sharedResult.sourceCount + privateResult.sourceCount,
      totalDestinationAfter: dstSharedCount + dstPrivateCount,
    };
  } finally {
    // Always close both temporary connections, success or failure.
    await srcConn.close().catch(() => {});
    await dstConn.close().catch(() => {});
  }
}

// Express handler. Gated behind MIGRATION_SECRET.
async function handleMigrate(req, res) {
  const expected = process.env.MIGRATION_SECRET;
  if (!expected) {
    return res.status(500).json({ ok: false, error: "MIGRATION_SECRET is not set on the server." });
  }
  if (req.query.secret !== expected) {
    return res.status(403).json({ ok: false, error: "forbidden" });
  }
  try {
    const result = await runMigration();
    res.json(result);
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
}

module.exports = { handleMigrate };
