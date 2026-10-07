/**
 * Attack Timeline Scrubber & Replay Controller
 */

class AttackTimelineController {
  constructor(trackContainerId, indicatorId) {
    this.container = document.getElementById(trackContainerId);
    this.indicator = document.getElementById(indicatorId);
    this.stages = [];
    this.currentStep = 0;
    this.isPlaying = false;
    this.playTimer = null;
    this.onStageSelect = null;
  }

  setStages(stages) {
    this.stages = stages || [];
    this.currentStep = 0;
    this.stopReplay();
    this.render();
  }

  render() {
    if (!this.container) return;

    if (!this.stages || this.stages.length === 0) {
      this.container.innerHTML = '';
      if (this.indicator) this.indicator.textContent = 'Stage 0/0';
      return;
    }

    if (this.indicator) {
      this.indicator.textContent = `Stage ${this.currentStep + 1} of ${this.stages.length}`;
    }

    let html = '';
    this.stages.forEach((stage, idx) => {
      const isActive = idx === this.currentStep;
      const confidencePct = Math.round(stage.proof.confidence * 100);

      html += `
        <div class="stage-card ${isActive ? 'active' : ''}" data-stage-idx="${idx}">
          <div class="stage-marker">${stage.stage_id}</div>
          <div class="stage-header">
            <span class="stage-tactic-badge">${stage.tactic}</span>
            <span class="stage-time">${stage.timestamp.replace('T', ' ').replace('Z', ' UTC')}</span>
          </div>
          <h4 class="stage-title">${stage.technique_id}: ${stage.technique_name}</h4>
          <p class="stage-desc">${stage.description}</p>
          <div class="stage-footer">
            <span><strong>Actor:</strong> ${stage.actor}</span>
            <span class="stage-confidence">Forensic Proof: ${confidencePct}% Confident</span>
          </div>
        </div>
      `;
    });

    this.container.innerHTML = html;

    // Attach click listeners to stage cards
    const cards = this.container.querySelectorAll('.stage-card');
    cards.forEach(card => {
      card.addEventListener('click', () => {
        const idx = parseInt(card.getAttribute('data-stage-idx'), 10);
        this.selectStep(idx);
      });
    });
  }

  selectStep(idx) {
    if (idx < 0 || idx >= this.stages.length) return;
    this.currentStep = idx;

    const cards = this.container.querySelectorAll('.stage-card');
    cards.forEach((c, i) => {
      if (i === idx) {
        c.classList.add('active');
        c.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      } else {
        c.classList.remove('active');
      }
    });

    if (this.indicator) {
      this.indicator.textContent = `Stage ${this.currentStep + 1} of ${this.stages.length}`;
    }

    if (this.onStageSelect) {
      this.onStageSelect(this.stages[idx]);
    }
  }

  nextStep() {
    if (this.currentStep < this.stages.length - 1) {
      this.selectStep(this.currentStep + 1);
    } else {
      this.selectStep(0);
    }
  }

  togglePlay() {
    if (this.isPlaying) {
      this.stopReplay();
    } else {
      this.startReplay();
    }
  }

  startReplay() {
    if (this.stages.length === 0) return;
    this.isPlaying = true;
    const playBtn = document.getElementById('btn-replay-play');
    if (playBtn) playBtn.innerHTML = '<span class="btn-icon">⏸</span> Pause Replay';

    this.playTimer = setInterval(() => {
      this.nextStep();
    }, 2800);
  }

  stopReplay() {
    this.isPlaying = false;
    if (this.playTimer) {
      clearInterval(this.playTimer);
      this.playTimer = null;
    }
    const playBtn = document.getElementById('btn-replay-play');
    if (playBtn) playBtn.innerHTML = '<span class="btn-icon">▶</span> Play Replay';
  }
}

window.AttackTimelineController = AttackTimelineController;
