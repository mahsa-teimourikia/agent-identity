const LEVEL_ORDER = { beginner: 0, intermediate: 1, advanced: 2 };
const STORAGE_KEY = 'agent-identity-hub-progress-v1';

function filterLessons(lessons, { level = 'all', query = '' } = {}) {
  const words = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
  return lessons.filter((lesson) => {
    const levelMatches = level === 'all' || lesson.level === level;
    const haystack = [lesson.title, lesson.summary, ...(lesson.outcomes || [])].join(' ').toLowerCase();
    return levelMatches && words.every((word) => haystack.includes(word));
  });
}

function nextIncomplete(lessons, completedIds, lastId = '') {
  if (!lessons.length) return null;
  const start = Math.max(0, lessons.findIndex((lesson) => lesson.id === lastId) + 1);
  const ordered = [...lessons.slice(start), ...lessons.slice(0, start)];
  return ordered.find((lesson) => !completedIds.has(lesson.id)) || lessons[lessons.length - 1];
}

function escapeHTML(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[character]));
}

function safeExternalLink(url, label) {
  if (!/^https:\/\//.test(url || '')) return '';
  return `<a href="${escapeHTML(url)}" target="_blank" rel="noreferrer">${escapeHTML(label)}</a>`;
}

function initHub(lessons) {
  const elements = {
    cards: document.querySelector('#lessons'),
    workspace: document.querySelector('#workspace'),
    search: document.querySelector('#search'),
    resultCount: document.querySelector('#result-count'),
    empty: document.querySelector('#empty-state'),
    progress: document.querySelector('#progress'),
    progressCount: document.querySelector('#progress-count'),
    continueButton: document.querySelector('#continue'),
    completeButton: document.querySelector('#complete-course'),
    status: document.querySelector('#status')
  };
  let saved = readSaved();
  let completed = new Set(saved.completed.filter((id) => lessons.some((lesson) => lesson.id === id)));
  let activeLevel = 'all';
  let activeLesson = null;

  function readSaved() {
    try {
      const value = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
      return { completed: Array.isArray(value.completed) ? value.completed : [], lastId: value.lastId || '' };
    } catch (_error) {
      return { completed: [], lastId: '' };
    }
  }

  function persist() {
    saved = { completed: [...completed], lastId: activeLesson?.id || saved.lastId };
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(saved)); } catch (_error) { /* private mode */ }
  }

  function announce(message) {
    elements.status.textContent = '';
    window.setTimeout(() => { elements.status.textContent = message; }, 20);
  }

  function updateProgress() {
    elements.progress.max = lessons.length;
    elements.progress.value = completed.size;
    elements.progress.textContent = `${Math.round((completed.size / lessons.length) * 100)}%`;
    elements.progressCount.textContent = `${completed.size} of ${lessons.length} complete`;
    const next = nextIncomplete(lessons, completed, saved.lastId);
    elements.continueButton.textContent = completed.size ? 'Continue learning' : 'Start learning';
    elements.continueButton.disabled = !next;
  }

  function renderCards() {
    const visible = filterLessons(lessons, { level: activeLevel, query: elements.search.value });
    elements.resultCount.textContent = `${visible.length} course${visible.length === 1 ? '' : 's'}`;
    elements.empty.hidden = visible.length > 0;
    elements.cards.replaceChildren(...visible.map((lesson) => {
      const card = document.createElement('article');
      card.className = `card${completed.has(lesson.id) ? ' complete' : ''}${activeLesson?.id === lesson.id ? ' selected' : ''}`;
      const button = document.createElement('button');
      button.type = 'button';
      button.dataset.courseId = lesson.id;
      button.setAttribute('aria-label', `Open ${lesson.title}`);
      button.innerHTML = `
        <span class="card-top"><span class="badge">${escapeHTML(lesson.level)} · ${lesson.levelStep}</span><span class="completion">${completed.has(lesson.id) ? '✓ Complete' : `Step ${lesson.step}`}</span></span>
        <h3>${escapeHTML(lesson.title)}</h3>
        <p>${escapeHTML(lesson.summary)}</p>
        <span class="open-label">Open course →</span>`;
      button.addEventListener('click', () => openLesson(lesson.id));
      card.append(button);
      return card;
    }));
  }

  function selectTab(name, moveFocus = false) {
    document.querySelectorAll('[role="tab"]').forEach((tab) => {
      const selected = tab.dataset.tab === name;
      tab.classList.toggle('active', selected);
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
      if (selected && moveFocus) tab.focus();
    });
    ['learn', 'lab', 'checkpoint'].forEach((id) => {
      document.querySelector(`#${id}`).hidden = id !== name;
    });
  }

  function renderLearn(lesson) {
    const outcomes = lesson.outcomes.map((outcome) => `<li>${escapeHTML(outcome)}</li>`).join('');
    const references = lesson.references.length
      ? `<h3>Selected sources</h3><ul class="reference-list">${lesson.references.map((reference) => `<li>${safeExternalLink(reference.url, reference.label)}</li>`).join('')}</ul>`
      : '';
    document.querySelector('#learn').innerHTML = `
      <h3>What you will be able to do</h3>
      <ul>${outcomes}</ul>
      <h3>Course material</h3>
      <p>${escapeHTML(lesson.detail)}</p>
      <p>${safeExternalLink(lesson.material, 'Read the complete, source-backed course on GitHub →')}</p>
      ${references}`;
  }

  function renderLab(lesson) {
    const links = [
      lesson.notebook && safeExternalLink(lesson.notebook, 'Open the guided notebook →'),
      lesson.lab && safeExternalLink(lesson.lab, 'Inspect the reusable lab →')
    ].filter(Boolean);
    const run = lesson.run ? `<h3>Run the practical path</h3><pre><code>${escapeHTML(lesson.run)}</code></pre>` : '';
    document.querySelector('#lab').innerHTML = `
      <h3>Practical implementation</h3>
      <p>The lab applies this course to a realistic enterprise scenario with labelled valid and adversarial cases.</p>
      ${links.length ? `<ul class="resource-links">${links.map((link) => `<li>${link}</li>`).join('')}</ul>` : '<p>Follow the practical instructions in the course material.</p>'}
      ${run}
      <p class="muted">Use the course requirements and setup instructions. Labs use synthetic fixtures and must never receive production credentials or personal data.</p>`;
  }

  function renderCheckpoint(lesson) {
    const question = lesson.checkpoint;
    document.querySelector('#checkpoint').innerHTML = `
      <h3>Course checkpoint</h3>
      <p>Test the control boundary before moving on. Your answer stays in this browser.</p>
      <fieldset class="question">
        <legend>${escapeHTML(question.text)}</legend>
        ${question.options.map((option, index) => `<label><input type="radio" name="checkpoint" value="${index}"> <span>${escapeHTML(option)}</span></label>`).join('')}
      </fieldset>
      <button id="check-answer" class="primary" type="button">Check answer</button>
      <p id="checkpoint-feedback" class="feedback" aria-live="polite"></p>
      <p><a href="quiz/?course=${encodeURIComponent(lesson.id)}">Practice every question for this course →</a></p>`;
    document.querySelector('#check-answer').addEventListener('click', () => {
      const selected = document.querySelector('input[name="checkpoint"]:checked');
      const feedback = document.querySelector('#checkpoint-feedback');
      if (!selected) {
        feedback.textContent = 'Choose an answer before checking.';
        feedback.className = 'feedback warning';
        return;
      }
      const correct = Number(selected.value) === question.answer;
      feedback.textContent = `${correct ? 'Correct' : `Review — correct answer: ${question.options[question.answer]}`}. ${question.explanation}`;
      feedback.className = `feedback ${correct ? 'success' : 'warning'}`;
    });
  }

  function openLesson(id, options = {}) {
    const lesson = lessons.find((candidate) => candidate.id === id);
    if (!lesson) return;
    activeLesson = lesson;
    saved.lastId = lesson.id;
    persist();
    document.querySelector('#level').textContent = `${lesson.level} · course ${lesson.levelStep} · step ${lesson.step} of ${lessons.length}`;
    document.querySelector('#title').textContent = lesson.title;
    document.querySelector('#summary').textContent = lesson.summary;
    document.querySelector('#position').textContent = `${lesson.step} / ${lessons.length}`;
    elements.completeButton.textContent = completed.has(lesson.id) ? '✓ Completed — mark incomplete' : 'Mark course complete';
    elements.completeButton.setAttribute('aria-pressed', String(completed.has(lesson.id)));
    document.querySelector('#previous-course').disabled = lesson.step === 1;
    document.querySelector('#next-course').disabled = lesson.step === lessons.length;
    renderLearn(lesson);
    renderLab(lesson);
    renderCheckpoint(lesson);
    selectTab('learn');
    elements.workspace.hidden = false;
    history.replaceState(null, '', `#course=${encodeURIComponent(lesson.id)}`);
    renderCards();
    if (options.scroll !== false) elements.workspace.scrollIntoView({ behavior: 'smooth', block: 'start' });
    announce(`Opened ${lesson.title}`);
  }

  document.querySelectorAll('[data-level]').forEach((button) => {
    button.addEventListener('click', () => {
      activeLevel = button.dataset.level;
      document.querySelectorAll('[data-level]').forEach((candidate) => {
        const active = candidate === button;
        candidate.classList.toggle('active', active);
        candidate.setAttribute('aria-pressed', String(active));
      });
      renderCards();
    });
  });
  elements.search.addEventListener('input', renderCards);
  elements.continueButton.addEventListener('click', () => {
    const lesson = nextIncomplete(lessons, completed, saved.lastId);
    if (lesson) openLesson(lesson.id);
  });
  elements.completeButton.addEventListener('click', () => {
    if (!activeLesson) return;
    if (completed.has(activeLesson.id)) completed.delete(activeLesson.id); else completed.add(activeLesson.id);
    persist();
    updateProgress();
    renderCards();
    elements.completeButton.textContent = completed.has(activeLesson.id) ? '✓ Completed — mark incomplete' : 'Mark course complete';
    elements.completeButton.setAttribute('aria-pressed', String(completed.has(activeLesson.id)));
    announce(`${activeLesson.title} marked ${completed.has(activeLesson.id) ? 'complete' : 'incomplete'}`);
  });
  document.querySelector('#reset-progress').addEventListener('click', () => {
    if (!completed.size || !window.confirm('Reset completion status for every course?')) return;
    completed = new Set();
    persist();
    updateProgress();
    renderCards();
    if (activeLesson) elements.completeButton.textContent = 'Mark course complete';
    announce('Saved progress reset');
  });
  document.querySelector('#previous-course').addEventListener('click', () => activeLesson && openLesson(lessons[activeLesson.step - 2]?.id));
  document.querySelector('#next-course').addEventListener('click', () => activeLesson && openLesson(lessons[activeLesson.step]?.id));
  document.querySelectorAll('[role="tab"]').forEach((tab) => {
    tab.addEventListener('click', () => selectTab(tab.dataset.tab));
    tab.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
      const tabs = [...document.querySelectorAll('[role="tab"]')];
      const offset = event.key === 'ArrowRight' ? 1 : -1;
      const next = tabs[(tabs.indexOf(tab) + offset + tabs.length) % tabs.length];
      selectTab(next.dataset.tab, true);
    });
  });

  updateProgress();
  renderCards();
  const hashCourse = new URLSearchParams(location.hash.replace(/^#/, '')).get('course');
  if (hashCourse && lessons.some((lesson) => lesson.id === hashCourse)) openLesson(hashCourse, { scroll: false });
}

if (typeof module !== 'undefined') module.exports = { filterLessons, nextIncomplete, escapeHTML };
if (typeof document !== 'undefined' && typeof LESSONS !== 'undefined') initHub(LESSONS);
