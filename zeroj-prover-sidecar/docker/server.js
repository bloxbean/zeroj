const express = require('express');
const snarkjs = require('snarkjs');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json({ limit: '10mb' }));

const CIRCUITS_DIR = process.env.CIRCUITS_DIR || '/circuits';
const PORT = process.env.PORT || 3000;

// Discover available circuits (each circuit has a directory with .wasm and .zkey files)
function discoverCircuits() {
    if (!fs.existsSync(CIRCUITS_DIR)) return {};
    const circuits = {};
    for (const name of fs.readdirSync(CIRCUITS_DIR)) {
        const dir = path.join(CIRCUITS_DIR, name);
        if (!fs.statSync(dir).isDirectory()) continue;

        const wasmFile = path.join(dir, `${name}.wasm`);
        const zkeyFile = path.join(dir, `${name}_final.zkey`);
        const vkFile = path.join(dir, 'verification_key.json');

        if (fs.existsSync(wasmFile) && fs.existsSync(zkeyFile)) {
            circuits[name] = { wasmFile, zkeyFile, vkFile };
            console.log(`[circuit] ${name}: wasm=${wasmFile}, zkey=${zkeyFile}`);
        }
    }
    return circuits;
}

let circuits = discoverCircuits();

// GET /health
app.get('/health', (req, res) => {
    res.json({ status: 'ok', circuits: Object.keys(circuits).length });
});

// GET /circuits
app.get('/circuits', (req, res) => {
    res.json(Object.keys(circuits));
});

// GET /circuits/:name/vk — fetch verification key
app.get('/circuits/:name/vk', (req, res) => {
    const circuit = circuits[req.params.name];
    if (!circuit) return res.status(404).json({ error: `Circuit '${req.params.name}' not found` });
    if (!fs.existsSync(circuit.vkFile)) {
        return res.status(404).json({ error: `VK not found for circuit '${req.params.name}'` });
    }
    const vk = fs.readFileSync(circuit.vkFile, 'utf-8');
    res.type('application/json').send(vk);
});

// POST /prove — generate a proof
app.post('/prove', async (req, res) => {
    const { circuit: circuitName, input } = req.body;

    if (!circuitName) return res.status(400).json({ error: 'Missing "circuit" field' });
    if (!input) return res.status(400).json({ error: 'Missing "input" field' });

    const circuit = circuits[circuitName];
    if (!circuit) return res.status(404).json({ error: `Circuit '${circuitName}' not found` });

    try {
        const startTime = Date.now();

        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            circuit.wasmFile,
            circuit.zkeyFile
        );

        const provingTimeMs = Date.now() - startTime;

        res.json({
            proof,
            publicSignals,
            protocol: proof.protocol || 'groth16',
            curve: proof.curve || 'bn128',
            provingTimeMs
        });
    } catch (err) {
        console.error(`[prove] Error for circuit '${circuitName}':`, err.message);
        res.status(500).json({ error: err.message });
    }
});

// Reload circuits (useful after mounting new volumes)
app.post('/reload', (req, res) => {
    circuits = discoverCircuits();
    res.json({ circuits: Object.keys(circuits) });
});

app.listen(PORT, () => {
    console.log(`ZeroJ prover sidecar listening on port ${PORT}`);
    console.log(`Circuits directory: ${CIRCUITS_DIR}`);
    console.log(`Available circuits: ${Object.keys(circuits).join(', ') || '(none)'}`);
});
