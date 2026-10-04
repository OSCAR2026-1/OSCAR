import { get_feed } from './index';
import 'dotenv/config';

async function runTest() {
    const testUrl = 'zhihu/hot';
    const testCount = 5;
    console.log(`--- Running test for: ${testUrl} with count: ${testCount} ---`);

    try {
        const feed = await get_feed({ url: testUrl, count: testCount });
        console.log("--- Test successful ---");
        console.log("--- Function Output: ---");
        console.log(JSON.stringify(feed, null, 2));

        // Let's simulate the client's expected structure
        const clientResponse = {
            structuredContent: feed
        };

        console.log("\n--- Simulated Client Response Payload: ---");
        console.log(JSON.stringify(clientResponse, null, 2));

        if (feed.items.length !== testCount) {
            throw new Error(`Expected ${testCount} items, but got ${feed.items.length}`);
        }

    } catch (error) {
        console.error("--- Test failed ---");
        console.error(error);
    }
}

runTest();