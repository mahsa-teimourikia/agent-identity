const QUIZ_STORAGE_KEY = 'agent-identity-quiz-best-v1';

function filterQuestions(questions, { level = 'all', courseId = 'all' } = {}) {
  return questions.filter((question) =>
    (level === 'all' || question.level === level) &&
    (courseId === 'all' || question.courseId === courseId)
  );
}

function hashSeed(value) {
  let hash = 2166136261;
  for (const character of String(value)) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function seededShuffle(items, seed) {
  const shuffled = [...items];
  let state = hashSeed(seed) || 1;
  const random = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 4294967296;
  };
  for (let index = shuffled.length - 1; index > 0; index -= 1) {
    const target = Math.floor(random() * (index + 1));
    [shuffled[index], shuffled[target]] = [shuffled[target], shuffled[index]];
  }
  return shuffled;
}

function selectQuestions(questions, options = {}) {
  const filtered = filterQuestions(questions, options);
  const shuffled = seededShuffle(filtered, options.seed || 1);
  const limit = options.limit === 'all' ? shuffled.length : Math.max(1, Number(options.limit) || 20);
  return shuffled.slice(0, limit);
}

function scoreQuiz(questions, answers) {
  const breakdown = {};
  let correct = 0;
  let answered = 0;
  questions.forEach((question) => {
    const value = answers[question.id];
    const hasAnswer = value !== undefined && value !== null && value !== '';
    const isCorrect = hasAnswer && Number(value) === question.answer;
    if (hasAnswer) answered += 1;
    if (isCorrect) correct += 1;
    breakdown[question.level] ||= { correct: 0, answered: 0, total: 0 };
    breakdown[question.level].total += 1;
    if (hasAnswer) breakdown[question.level].answered += 1;
    if (isCorrect) breakdown[question.level].correct += 1;
  });
  return {
    correct,
    answered,
    unanswered: questions.length - answered,
    total: questions.length,
    percent: questions.length ? Math.round((correct / questions.length) * 100) : 0,
    breakdown
  };
}

function escapeHTML(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[character]));
}

function initQuiz(questionBank) {
  const levelFilter = document.querySelector('#level-filter');
  const courseFilter = document.querySelector('#course-filter');
  const countFilter = document.querySelector('#question-count');
  const quizForm = document.querySelector('#quiz');
  const result = document.querySelector('#result');
  let attempt = 1;
  let activeQuestions = [];

  const courses = [...new Map(questionBank.map((question) => [question.courseId, {
    id: question.courseId,
    title: question.courseTitle,
    level: question.level,
    step: question.courseStep
  }])).values()].sort((a, b) => a.step - b.step);

  function readBestScores() {
    try { return JSON.parse(localStorage.getItem(QUIZ_STORAGE_KEY) || '{}'); } catch (_error) { return {}; }
  }

  function writeBestScores(scores) {
    try { localStorage.setItem(QUIZ_STORAGE_KEY, JSON.stringify(scores)); } catch (_error) { /* private mode */ }
  }

  function configuration() {
    return {
      level: levelFilter.value,
      courseId: courseFilter.value,
      limit: countFilter.value,
      seed: `${levelFilter.value}:${courseFilter.value}:${countFilter.value}:${attempt}`
    };
  }

  function signature() {
    const config = configuration();
    return `${config.level}|${config.courseId}|${config.limit}`;
  }

  function updateBestLabel() {
    const best = readBestScores()[signature()];
    document.querySelector('#best-score').textContent = best
      ? `Best for this scope: ${best.correct}/${best.total} (${best.percent}%)`
      : 'No saved score for this scope yet';
  }

  function updateCourseOptions() {
    const current = courseFilter.value;
    const available = courses.filter((course) => levelFilter.value === 'all' || course.level === levelFilter.value);
    courseFilter.replaceChildren(new Option('All courses', 'all'), ...available.map((course) => new Option(`${course.step}. ${course.title}`, course.id)));
    courseFilter.value = available.some((course) => course.id === current) ? current : 'all';
    updateBankSummary();
  }

  function updateBankSummary() {
    const available = filterQuestions(questionBank, configuration()).length;
    document.querySelector('#bank-summary').textContent = `${available} question${available === 1 ? '' : 's'} available in this scope.`;
  }

  function renderQuiz() {
    activeQuestions = selectQuestions(questionBank, configuration());
    result.hidden = true;
    quizForm.innerHTML = activeQuestions.map((question, index) => `
      <fieldset class="question" data-question-id="${escapeHTML(question.id)}">
        <legend><span>${index + 1}</span>${escapeHTML(question.text)}</legend>
        <p class="question-meta">${escapeHTML(question.level)} · course ${question.courseStep}: ${escapeHTML(question.courseTitle)}</p>
        ${question.options.map((option, optionIndex) => `
          <label>
            <input type="radio" name="${escapeHTML(question.id)}" value="${optionIndex}">
            <span>${escapeHTML(option)}</span>
          </label>`).join('')}
        <p class="explanation" aria-live="polite"></p>
      </fieldset>`).join('');
    const scope = courseFilter.value === 'all'
      ? (levelFilter.value === 'all' ? 'all levels' : levelFilter.value)
      : courses.find((course) => course.id === courseFilter.value)?.title;
    document.querySelector('#quiz-title').textContent = `${activeQuestions.length}-question check · ${scope}`;
    updateBestLabel();
    updateBankSummary();
  }

  function collectAnswers() {
    return Object.fromEntries(activeQuestions.map((question) => {
      const selected = quizForm.querySelector(`input[name="${CSS.escape(question.id)}"]:checked`);
      return [question.id, selected?.value];
    }));
  }

  function gradeQuiz() {
    const answers = collectAnswers();
    const score = scoreQuiz(activeQuestions, answers);
    activeQuestions.forEach((question) => {
      const fieldset = quizForm.querySelector(`[data-question-id="${CSS.escape(question.id)}"]`);
      const selected = answers[question.id];
      const correct = selected !== undefined && Number(selected) === question.answer;
      const explanation = fieldset.querySelector('.explanation');
      explanation.textContent = selected === undefined
        ? `Unanswered — correct answer: ${question.options[question.answer]}. ${question.explanation}`
        : `${correct ? 'Correct' : `Review — correct answer: ${question.options[question.answer]}`}. ${question.explanation}`;
      explanation.className = `explanation ${correct ? 'correct' : 'review'}`;
      fieldset.querySelectorAll('label').forEach((label, index) => {
        label.classList.toggle('correct-option', index === question.answer);
        label.classList.toggle('incorrect-option', Number(selected) === index && index !== question.answer);
      });
    });
    const breakdown = Object.entries(score.breakdown).map(([level, item]) =>
      `<li><strong>${escapeHTML(level)}</strong>: ${item.correct}/${item.total} correct (${item.answered} answered)</li>`
    ).join('');
    result.innerHTML = `
      <p class="score">${score.correct}/${score.total} · ${score.percent}%</p>
      <h2>${score.percent >= 80 ? 'Strong result' : score.percent >= 60 ? 'Keep building' : 'Review the foundations'}</h2>
      <p>${score.answered} answered · ${score.unanswered} unanswered. Unanswered questions count as incorrect.</p>
      <h3>Performance by level</h3><ul>${breakdown}</ul>
      <p>Use each explanation to return to the relevant course, then build a new set to check transfer.</p>`;
    result.hidden = false;
    result.focus();
    const bestScores = readBestScores();
    const previous = bestScores[signature()];
    if (!previous || score.percent > previous.percent || (score.percent === previous.percent && score.correct > previous.correct)) {
      bestScores[signature()] = { correct: score.correct, total: score.total, percent: score.percent };
      writeBestScores(bestScores);
    }
    updateBestLabel();
  }

  levelFilter.addEventListener('change', updateCourseOptions);
  courseFilter.addEventListener('change', updateBankSummary);
  countFilter.addEventListener('change', updateBankSummary);
  document.querySelector('#new-quiz').addEventListener('click', () => { attempt += 1; renderQuiz(); });
  document.querySelector('#grade').addEventListener('click', gradeQuiz);
  document.querySelector('#clear-answers').addEventListener('click', () => {
    quizForm.reset();
    quizForm.querySelectorAll('.explanation').forEach((element) => { element.textContent = ''; element.className = 'explanation'; });
    quizForm.querySelectorAll('label').forEach((label) => label.classList.remove('correct-option', 'incorrect-option'));
    result.hidden = true;
    quizForm.querySelector('input')?.focus();
  });

  updateCourseOptions();
  const requestedCourse = new URLSearchParams(location.search).get('course');
  if (requestedCourse && courses.some((course) => course.id === requestedCourse)) {
    const course = courses.find((candidate) => candidate.id === requestedCourse);
    levelFilter.value = course.level;
    updateCourseOptions();
    courseFilter.value = requestedCourse;
    countFilter.value = 'all';
  }
  renderQuiz();
}

if (typeof module !== 'undefined') module.exports = { filterQuestions, seededShuffle, selectQuestions, scoreQuiz, hashSeed };
if (typeof document !== 'undefined' && typeof QUESTIONS !== 'undefined') initQuiz(QUESTIONS);
