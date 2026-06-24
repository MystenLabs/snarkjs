module.exports = {
    // snarkjs CLI commands force process exit, but the library tests expose
    // legacy APIs that create ffjavascript curves without terminating workers.
    // The proper fix is to close internally-created curves in those APIs; this
    // branch keeps CI focused on the CLI ceremony path.
    exit: true,
};
