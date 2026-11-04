// electron-builder afterSign hook: notarize the signed macOS app with Apple's notary service.
// Runs only for macOS builds that were actually signed and when all three credentials are present:
//   APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, APPLE_TEAM_ID
// Otherwise it logs why and returns, so local and unsigned CI builds still succeed (Gatekeeper will warn on them).
// The built-in `mac.notarize` option is disabled in package.json so this hook is the single place it happens.
const path = require("path");

exports.default = async function notarizeApp(context) {
  const { electronPlatformName, appOutDir, packager } = context;
  if (electronPlatformName !== "darwin") return;
  const { APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, APPLE_TEAM_ID } = process.env;
  if (!APPLE_ID || !APPLE_APP_SPECIFIC_PASSWORD || !APPLE_TEAM_ID) {
    console.warn("  • notarization skipped: APPLE_ID / APPLE_APP_SPECIFIC_PASSWORD / APPLE_TEAM_ID not all set");
    return;
  }
  if (process.env.CSC_IDENTITY_AUTO_DISCOVERY === "false" && !process.env.CSC_LINK && !process.env.CSC_NAME) {
    console.warn("  • notarization skipped: the app was not signed (no CSC_LINK / CSC_NAME); Apple rejects unsigned apps");
    return;
  }
  const appPath = path.join(appOutDir, `${packager.appInfo.productFilename}.app`);
  console.log(`  • notarizing ${appPath} (team ${APPLE_TEAM_ID})`);
  const { notarize } = require("@electron/notarize");
  await notarize({
    appPath,
    appleId: APPLE_ID,
    appleIdPassword: APPLE_APP_SPECIFIC_PASSWORD,
    teamId: APPLE_TEAM_ID,
  });
  console.log("  • notarization complete (ticket stapled)");
};
