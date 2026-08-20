import os
import glob
import re
import json
import sys

# Import custom questions
try:
    from custom_questions import get_questions_for_module
except ImportError:
    def get_questions_for_module(mod):
        return [("What is a primary focus of this module?", ["The concepts taught in this module.", "An unrelated topic.", "Nothing."], 0, "Refer to the module README.")]

def parse_curriculum():
    levels = ['beginner', 'intermediate', 'advanced']
    lessons = []
    questions = []
    step = 1

    for level in levels:
        dirs = sorted(glob.glob(f"curriculum/{level}/*"))
        for d in dirs:
            if not os.path.isdir(d):
                continue
            
            readme_path = os.path.join(d, "README.md")
            if not os.path.exists(readme_path):
                continue

            with open(readme_path, 'r') as f:
                content = f.read()

            module_dir_name = os.path.basename(d)

            # Extract title
            title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
            title = title_match.group(1).split('—')[-1].strip() if title_match else module_dir_name

            # Extract goal/summary
            goal_match = re.search(r'>\s*\*\*Goal:\*\*\s*(.+?)(?=\n\n|\n>|\Z)', content, re.DOTALL | re.IGNORECASE)
            if goal_match:
                summary = goal_match.group(1).strip().replace('\n', ' ')
            else:
                summary = f"Learn about {title}"

            detail = summary

            # Find lab and notebook
            py_files = glob.glob(f"{d}/**/*.py", recursive=True)
            ipynb_files = glob.glob(f"{d}/**/*.ipynb", recursive=True)

            py_file = py_files[0] if py_files else None
            ipynb_file = ipynb_files[0] if ipynb_files else None
            
            # Repo base
            repo_base = "${REPO}/blob/main/"

            lesson = {
                'level': level,
                'step': step,
                'title': title,
                'summary': summary[:100] + "..." if len(summary) > 100 else summary,
                'detail': detail,
                'material': f"{repo_base}{readme_path}"
            }

            # Do not generate lab and run fields for .py files per user request
            
            if ipynb_file:
                lesson['notebook'] = f"{repo_base}{ipynb_file}"
            
            # Get custom questions
            custom_qs = get_questions_for_module(module_dir_name)
            
            # Use the first question for the lesson checkpoint
            q_text, q_options, q_answer, q_expl = custom_qs[0]
            lesson['q'] = [q_text, q_options, q_answer, q_expl]

            lessons.append(lesson)

            # Add all questions for this module to the quiz database
            for cq_text, cq_options, cq_answer, cq_expl in custom_qs:
                questions.append({
                    'level': level,
                    'text': cq_text,
                    'options': cq_options,
                    'answer': cq_answer,
                    'explanation': cq_expl
                })

            step += 1

    return lessons, questions

def write_lessons(lessons):
    lines = []
    lines.append("const REPO='https://github.com/mahsa-teimourikia/agent-identity';")
    lines.append("const LESSONS=[")
    
    for i, l in enumerate(lessons):
        props = []
        for k, v in l.items():
            if k in ['q', 'step', 'level', 'title', 'summary', 'detail', 'run']:
                props.append(f"{k}:{json.dumps(v)}")
            elif k in ['material', 'lab', 'notebook']:
                escaped_v = v.replace('`', '\\`')
                props.append(f"{k}:`{escaped_v}`")

        obj_str = "{" + ",".join(props) + "}"
        lines.append(obj_str + ("," if i < len(lessons)-1 else ""))
        
    lines.append("];")
    
    with open("hub/lessons.js", "w") as f:
        f.write("\n".join(lines))

def write_questions(questions):
    lines = []
    lines.append("const QUESTIONS=[")
    for i, q in enumerate(questions):
        obj_str = json.dumps(q)
        lines.append(obj_str + ("," if i < len(questions)-1 else ""))
    lines.append("];")
    
    with open("quiz/questions.js", "w") as f:
        f.write("\n".join(lines))

if __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    lessons, questions = parse_curriculum()
    write_lessons(lessons)
    write_questions(questions)
    print(f"Generated {len(lessons)} lessons and {len(questions)} questions.")
