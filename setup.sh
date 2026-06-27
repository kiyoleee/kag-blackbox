#!/bin/bash
set -e

WORK_DIR="${KAG_WORK_DIR:-/data/lqy/framework/kag-blackbox}"
CONDA_ENV="kag-blackbox"
NEO4J_URI="${NEO4J_URI:-bolt://127.0.0.1:7687}"
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES_DIR:-/opt/nuclei-templates/http}"

echo "============================================================"
echo "  KAG-Blackbox v1.0 Deployment"
echo "============================================================"
echo "  Work dir:  $WORK_DIR"
echo "  Conda env: $CONDA_ENV"
echo "  Neo4j:     $NEO4J_URI"
echo "============================================================"

# 1. Clone repo
if [ ! -d "$WORK_DIR" ]; then
    echo "[1/6] Cloning repository..."
    apt-get install -y git-lfs 2>/dev/null || yum install -y git-lfs 2>/dev/null || true
    git lfs install
    git clone https://github.com/kiyoleee/kag-blackbox.git "$WORK_DIR"
else
    echo "[1/6] Repo exists, pulling latest..."
    cd "$WORK_DIR" && git pull origin main
fi
cd "$WORK_DIR"

# 2. Conda environment
echo "[2/6] Setting up conda environment..."
if ! conda info --envs 2>/dev/null | grep -q "$CONDA_ENV"; then
    conda create -n "$CONDA_ENV" python=3.10 -y
fi
eval "$(conda shell.bash hook)"
conda activate "$CONDA_ENV"
pip install -r requirements.txt
pip install openpyxl  # for xlsx output

# 3. Unzip datasets
echo "[3/6] Extracting datasets..."
cd fingerprints
if [ ! -d "surper-666" ]; then
    unzip -o surper-666.zip
fi
if [ ! -d "other_vul" ] && [ -f "other_vul.zip" ]; then
    mkdir -p other_vul_tmp
fi
cd ..

# 4. Download Nuclei templates if not present
echo "[4/6] Checking Nuclei templates..."
if [ ! -d "$NUCLEI_TEMPLATES" ]; then
    echo "  Nuclei templates not found at $NUCLEI_TEMPLATES"
    echo "  Downloading..."
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates 2>/dev/null || true
fi

# 5. Build Knowledge Graph
echo "[5/6] Building Knowledge Graph..."
python3 kag_blackbox/builder/build_kg.py \
    --nuclei-dir "$NUCLEI_TEMPLATES" \
    --fingerprints fingerprints/surper-666/vulhub_fingerprints \
    --benchmark-fingerprints fingerprints/surper-666/benchmark_fingerprints \
    --surper-nuclei fingerprints/surper-666/nuclei \
    --other-vul fingerprints/other_vul.zip \
    --no-vulhub-mapping \
    --clear

# 6. Verify
echo "[6/6] Verifying installation..."
python3 -c "
from neo4j import GraphDatabase
d = GraphDatabase.driver('$NEO4J_URI', auth=('neo4j', 'neo4j@openspg'))
with d.session() as s:
    for label in ['BB_Product', 'BB_CVE', 'BB_PoC', 'BB_Fingerprint']:
        cnt = s.run(f'MATCH (n:{label}) RETURN count(n) AS c').single()['c']
        print(f'  {label}: {cnt}')
d.close()
"

echo ""
echo "============================================================"
echo "  Deployment complete!"
echo "============================================================"
echo ""
echo "  Activate environment:  conda activate $CONDA_ENV"
echo ""
echo "  Run scan:"
echo "    python3 scanner/competition_scanner.py \\"
echo "      --targets targets.txt \\"
echo "      --neo4j-uri $NEO4J_URI \\"
echo "      --fp-dir fingerprints/surper-666/vulhub_fingerprints \\"
echo "      --llm-url http://127.0.0.1:8200/v1 \\"
echo "      --llm-model qwen36-35b-a3b \\"
echo "      --workers 5 --no-fallback"
echo ""
