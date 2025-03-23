import Hyperswarm from 'hyperswarm';
import crypto from 'crypto';

const swarm = new Hyperswarm();
const topic = crypto.createHash('sha256').update("test-peer").digest();

swarm.join(topic, { server: true });

(async () => {
    await swarm.flush();
    console.log("Swarm has fully announced itself.");
})();

setInterval(() => {
    console.log(`Connected peers: ${swarm.peers.size}`);
}, 5000);

swarm.on("connection", () => {
    console.log("New peer connected");
});


// const app = express()
// app.use(express.json())

// app.listen(4100, () => {
//     console.log('port on 4100')
// })