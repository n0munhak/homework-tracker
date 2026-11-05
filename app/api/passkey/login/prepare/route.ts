import { MongoClient } from "mongodb";
import { generateAuthenticationOptions } from '@simplewebauthn/server';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
    const client = new MongoClient(process.env.MONGO!);
    await client.connect();
    const db = client.db(process.env.DB_NAME);
    const sessionsCollection = db.collection('loginSessions');
    const options = await generateAuthenticationOptions({
        rpID: new URL('/', process.env.NEXT_PUBLIC_URL || 'http://localhost:3000').hostname,
        userVerification: 'required'
    });
    const sessionArray = new Uint8Array(32);
    crypto.getRandomValues(sessionArray);
    const session = Array.from(sessionArray).map(b => b.toString(16).padStart(2, '0')).join('');
    const hashedSession = await globalThis.crypto.subtle.digest('SHA-512', sessionArray);
    const hashedSessionString = Buffer.from(hashedSession).toString('hex');
    await sessionsCollection.insertOne({ session: hashedSessionString, challenge: options.challenge });
    return new Response(JSON.stringify({ code: 0, session, options }), { status: 200 });
}
