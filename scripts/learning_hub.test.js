const test = require('node:test');
const assert = require('node:assert/strict');

const hub = require('../hub/app.js');
const quiz = require('../quiz/app.js');

const lessons = [
  { id: 'beginner/one', level: 'beginner', title: 'Identity foundations', summary: 'Separate principals', outcomes: ['Model identities'] },
  { id: 'advanced/two', level: 'advanced', title: 'Delegation', summary: 'Bound authority', outcomes: ['Attenuate grants'] },
  { id: 'advanced/three', level: 'advanced', title: 'Audit evidence', summary: 'Reconstruct decisions', outcomes: ['Preserve evidence'] }
];

const questions = [
  { id: 'q1', level: 'beginner', courseId: 'beginner/one', answer: 0 },
  { id: 'q2', level: 'advanced', courseId: 'advanced/two', answer: 1 },
  { id: 'q3', level: 'advanced', courseId: 'advanced/three', answer: 2 }
];

test('Hub filters by level and searches outcomes and summaries', () => {
  assert.deepEqual(hub.filterLessons(lessons, { level: 'advanced' }).map((item) => item.id), ['advanced/two', 'advanced/three']);
  assert.deepEqual(hub.filterLessons(lessons, { query: 'preserve evidence' }).map((item) => item.id), ['advanced/three']);
});

test('Hub continues after the last visited course and wraps to incomplete work', () => {
  assert.equal(hub.nextIncomplete(lessons, new Set(['beginner/one']), 'beginner/one').id, 'advanced/two');
  assert.equal(hub.nextIncomplete(lessons, new Set(['beginner/one', 'advanced/two']), 'advanced/three').id, 'advanced/three');
});

test('Quiz filtering and seeded selection are deterministic', () => {
  assert.deepEqual(quiz.filterQuestions(questions, { level: 'advanced' }).map((item) => item.id), ['q2', 'q3']);
  assert.deepEqual(quiz.selectQuestions(questions, { seed: 'same', limit: 2 }), quiz.selectQuestions(questions, { seed: 'same', limit: 2 }));
});

test('Quiz scoring counts unanswered questions and produces level breakdowns', () => {
  const score = quiz.scoreQuiz(questions, { q1: 0, q2: 0 });
  assert.deepEqual({ correct: score.correct, answered: score.answered, unanswered: score.unanswered, total: score.total, percent: score.percent }, {
    correct: 1, answered: 2, unanswered: 1, total: 3, percent: 33
  });
  assert.deepEqual(score.breakdown.advanced, { correct: 0, answered: 1, total: 2 });
});

test('HTML escaping protects learner-facing generated content', () => {
  assert.equal(hub.escapeHTML('<script>"x"</script>'), '&lt;script&gt;&quot;x&quot;&lt;/script&gt;');
});
