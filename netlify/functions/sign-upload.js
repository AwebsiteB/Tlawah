const crypto = require('crypto');

// Firebase Web API key — this is NOT a secret (Firebase API keys only identify
// the project; real protection comes from Firestore/Auth rules), so it's safe
// to keep it here directly.
const FIREBASE_WEB_API_KEY = 'AIzaSyDOxL5o-gjUmRxvNn6yBc1Yd_Po7_yUOcg';

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method Not Allowed' }) };
  }

  try {
    const { idToken } = JSON.parse(event.body || '{}');
    if (!idToken) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Missing idToken' }) };
    }

    const verifyRes = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_WEB_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken })
      }
    );
    const verifyJson = await verifyRes.json();

    if (!verifyRes.ok || !verifyJson.users || verifyJson.users.length === 0) {
      return { statusCode: 401, body: JSON.stringify({ error: 'Unauthorized' }) };
    }

    const apiSecret = process.env.CLOUDINARY_API_SECRET;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const timestamp = Math.floor(Date.now() / 1000);
    const paramsToSign = `timestamp=${timestamp}`;
    const signature = crypto
      .createHash('sha1')
      .update(paramsToSign + apiSecret)
      .digest('hex');

    return {
      statusCode: 200,
      body: JSON.stringify({ signature, timestamp, apiKey })
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
