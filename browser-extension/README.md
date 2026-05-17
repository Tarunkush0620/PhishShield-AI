# PhishShield AI Browser Extension

This folder contains a Manifest V3 browser extension that connects to the existing PhishShield AI Flask API.

## Features

- Scan the current tab URL
- Scan selected text from the page
- Scan pasted email text or suspicious messages
- Run bulk URL scans
- Automatically scan pages when they load or when you switch tabs
- Automatically scan open Gmail messages and show an email threat analysis banner
- Show a warning banner on suspicious pages
- Store recent scan history locally
- Use the existing backend explanation fields for threat signals and contributions

## Local setup

1. Make sure the Flask app is running at `http://127.0.0.1:5000`.
2. Open `chrome://extensions` or `edge://extensions`.
3. Enable Developer Mode.
4. Load unpacked and select this `browser-extension` folder.
5. Open any website, then click the PhishShield icon.

## Notes

- The extension defaults to `http://127.0.0.1:5000` but you can change the API base URL in the popup.
- Privacy mode is enabled by default and redacts personal identifiers locally before email analysis.
- Auto-scan is enabled by default and can be turned off in the popup.
- The background worker uses the Flask API endpoints directly, so no extra backend work is required.
- For real deployment, update the API base URL to your hosted Flask app.
