
const inspectHandler = require("../inspect");

module.exports = async function handler(req, res) {
  try {
    return await inspectHandler(req, res);
  } catch (error) {
    console.error("Inspect API route failed.");

    if (res.headersSent) {
      return;
    }

    return res.status(500).json({
      error: "Internal server error",
      decision: "BLOCK",
      source: "Server error",
      modelCalled: false
    });
  }
};
