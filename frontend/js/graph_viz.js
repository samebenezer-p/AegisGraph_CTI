/**
 * AegisGraph-CTI Interactive Provenance Graph Visualizer
 * Force-directed and structured layout engine for Entity-Event Provenance Graphs.
 */

class ProvenanceGraphVisualizer {
  constructor(svgElementId, containerId) {
    this.svg = document.getElementById(svgElementId);
    this.container = document.getElementById(containerId);
    this.nodes = [];
    this.edges = [];
    this.showLabels = true;
    this.panX = 0;
    this.panY = 0;
    this.zoom = 1;
    this.isDragging = false;
    this.dragStartX = 0;
    this.dragStartY = 0;
    this.selectedNodeId = null;

    this.initEventListeners();
  }

  initEventListeners() {
    this.svg.addEventListener('mousedown', (e) => {
      if (e.target.closest('.graph-node')) return;
      this.isDragging = true;
      this.dragStartX = e.clientX - this.panX;
      this.dragStartY = e.clientY - this.panY;
    });

    window.addEventListener('mousemove', (e) => {
      if (!this.isDragging) return;
      this.panX = e.clientX - this.dragStartX;
      this.panY = e.clientY - this.dragStartY;
      this.applyTransform();
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
    });

    this.svg.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
      this.zoom = Math.max(0.4, Math.min(2.5, this.zoom * zoomFactor));
      this.applyTransform();
    });
  }

  resetView() {
    this.panX = 0;
    this.panY = 0;
    this.zoom = 1;
    this.applyTransform();
  }

  toggleLabels() {
    this.showLabels = !this.showLabels;
    this.render();
  }

  setData(nodes, edges) {
    this.nodes = nodes || [];
    this.edges = edges || [];
    this.layoutNodes();
    this.render();
  }

  layoutNodes() {
    const width = this.container.clientWidth || 800;
    const height = this.container.clientHeight || 500;
    const centerX = width / 2;
    const centerY = height / 2;

    // Group nodes by entity type for clear layered provenance architecture
    const layers = {
      "IP": [],
      "User": [],
      "Host": [],
      "Process": [],
      "File": [],
      "Device": []
    };

    this.nodes.forEach(node => {
      if (layers[node.type]) {
        layers[node.type].push(node);
      } else {
        layers["Host"].push(node);
      }
    });

    // Layer X positions
    const layerKeys = Object.keys(layers).filter(k => layers[k].length > 0);
    const colSpacing = (width - 180) / Math.max(1, layerKeys.length - 1);

    layerKeys.forEach((key, colIdx) => {
      const colNodes = layers[key];
      const x = 90 + colIdx * colSpacing;
      const rowSpacing = Math.min(100, (height - 120) / Math.max(1, colNodes.length));
      const startY = centerY - ((colNodes.length - 1) * rowSpacing) / 2;

      colNodes.forEach((node, rowIdx) => {
        node.x = x + (Math.sin(rowIdx) * 15);
        node.y = startY + rowIdx * rowSpacing;
      });
    });
  }

  applyTransform() {
    const group = this.svg.querySelector('#graph-root-group');
    if (group) {
      group.setAttribute('transform', `translate(${this.panX}, ${this.panY}) scale(${this.zoom})`);
    }
  }

  getNodeColor(node) {
    if (node.is_compromised) return '#f43f5e';
    switch (node.type) {
      case 'User': return '#3b82f6';
      case 'Host': return '#8b5cf6';
      case 'IP': return '#f59e0b';
      case 'Process': return '#06b6d4';
      case 'File': return '#eab308';
      case 'Device': return '#ec4899';
      default: return '#94a3b8';
    }
  }

  render() {
    this.svg.innerHTML = `
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
        </marker>
        <marker id="arrow-attack" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#f43f5e" />
        </marker>
        <filter id="glow-attack" x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="5" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>
      </defs>
      <g id="graph-root-group"></g>
    `;

    const group = this.svg.querySelector('#graph-root-group');
    const nodeMap = new Map();
    this.nodes.forEach(n => nodeMap.set(n.id, n));

    // 1. Draw Edges
    this.edges.forEach(edge => {
      const src = nodeMap.get(edge.source);
      const tgt = nodeMap.get(edge.target);
      if (!src || !tgt) return;

      const isAttack = edge.is_suspicious;
      const edgeElem = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      edgeElem.setAttribute('class', `graph-edge ${isAttack ? 'attack-edge' : ''}`);

      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', src.x);
      line.setAttribute('y1', src.y);
      line.setAttribute('x2', tgt.x);
      line.setAttribute('y2', tgt.y);
      line.setAttribute('stroke', isAttack ? '#f43f5e' : 'rgba(255, 255, 255, 0.15)');
      line.setAttribute('stroke-width', isAttack ? '2.5' : '1.5');
      if (isAttack) {
        line.setAttribute('stroke-dasharray', '6 3');
        line.setAttribute('filter', 'url(#glow-attack)');
      }
      line.setAttribute('marker-end', isAttack ? 'url(#arrow-attack)' : 'url(#arrow)');

      edgeElem.appendChild(line);

      // Edge relation label
      if (this.showLabels) {
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', (src.x + tgt.x) / 2);
        text.setAttribute('y', (src.y + tgt.y) / 2 - 5);
        text.setAttribute('fill', isAttack ? '#fda4af' : '#64748b');
        text.setAttribute('font-family', 'JetBrains Mono, monospace');
        text.setAttribute('font-size', '9px');
        text.setAttribute('text-anchor', 'middle');
        text.textContent = edge.relation;
        edgeElem.appendChild(text);
      }

      group.appendChild(edgeElem);
    });

    // 2. Draw Nodes
    this.nodes.forEach(node => {
      const nodeElem = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      nodeElem.setAttribute('class', `graph-node ${node.is_compromised ? 'compromised' : ''}`);
      nodeElem.setAttribute('transform', `translate(${node.x}, ${node.y})`);
      nodeElem.style.cursor = 'pointer';

      // Pulse ring for compromised nodes
      if (node.is_compromised) {
        const ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        ring.setAttribute('r', '22');
        ring.setAttribute('fill', 'none');
        ring.setAttribute('stroke', '#f43f5e');
        ring.setAttribute('stroke-width', '1.5');
        ring.setAttribute('opacity', '0.6');
        ring.innerHTML = `<animate attributeName="r" values="18;28;18" dur="2s" repeatCount="indefinite"/>
                          <animate attributeName="opacity" values="0.8;0.1;0.8" dur="2s" repeatCount="indefinite"/>`;
        nodeElem.appendChild(ring);
      }

      // Base circle
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('r', '16');
      circle.setAttribute('fill', this.getNodeColor(node));
      circle.setAttribute('stroke', node.is_compromised ? '#fff' : 'rgba(255, 255, 255, 0.4)');
      circle.setAttribute('stroke-width', node.is_compromised ? '2.5' : '1.5');
      if (node.is_compromised) {
        circle.setAttribute('filter', 'url(#glow-attack)');
      }
      nodeElem.appendChild(circle);

      // Icon / Initials inside node
      const iconText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      iconText.setAttribute('text-anchor', 'middle');
      iconText.setAttribute('dy', '4');
      iconText.setAttribute('fill', '#fff');
      iconText.setAttribute('font-size', '10px');
      iconText.setAttribute('font-weight', '700');
      iconText.setAttribute('font-family', 'Inter, sans-serif');
      iconText.textContent = node.type.charAt(0);
      nodeElem.appendChild(iconText);

      // Label below node
      if (this.showLabels) {
        const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        label.setAttribute('text-anchor', 'middle');
        label.setAttribute('dy', '28');
        label.setAttribute('fill', node.is_compromised ? '#fda4af' : '#cbd5e1');
        label.setAttribute('font-size', '10px');
        label.setAttribute('font-family', 'JetBrains Mono, monospace');
        label.setAttribute('font-weight', node.is_compromised ? '700' : '500');
        label.textContent = node.label.length > 16 ? node.label.substring(0, 14) + '..' : node.label;
        nodeElem.appendChild(label);
      }

      // Node Click handler
      nodeElem.addEventListener('click', (e) => {
        e.stopPropagation();
        this.selectNode(node);
      });

      group.appendChild(nodeElem);
    });

    this.applyTransform();
  }

  selectNode(node) {
    this.selectedNodeId = node.id;
    const flyout = document.getElementById('node-inspector-flyout');
    const typeBadge = document.getElementById('inspect-type');
    const nameLabel = document.getElementById('inspect-label');
    const detailsContainer = document.getElementById('inspect-details');

    if (!flyout) return;

    flyout.classList.remove('hidden');
    typeBadge.textContent = node.type.toUpperCase();
    nameLabel.textContent = node.label;

    let detailsHtml = `
      <div><strong>Internal ID:</strong> <code>${node.id}</code></div>
      <div><strong>Compromised Status:</strong> <span style="color:${node.is_compromised ? '#f43f5e' : '#10b981'}">
        ${node.is_compromised ? '🚨 COMPROMISED' : '✅ CLEAN / BENIGN'}
      </span></div>
      <div><strong>Risk Contribution:</strong> ${node.risk_score} / 100</div>
    `;

    if (node.attributes) {
      for (const [key, val] of Object.entries(node.attributes)) {
        detailsHtml += `<div><strong>${key}:</strong> <code>${val}</code></div>`;
      }
    }

    detailsContainer.innerHTML = detailsHtml;
  }
}

window.ProvenanceGraphVisualizer = ProvenanceGraphVisualizer;
