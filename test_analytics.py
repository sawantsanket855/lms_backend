import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv

load_dotenv()

try:
    conn = psycopg2.connect(
        host=os.getenv('POSTGRES_HOST'),
        port=os.getenv('POSTGRES_PORT'),
        dbname=os.getenv('POSTGRES_DB'),
        user=os.getenv('POSTGRES_USER'),
        password=os.getenv('POSTGRES_PASSWORD')
    )
    db = conn
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # get a user ID that has session progress
    cur.execute("SELECT user_id FROM lms_session_progress LIMIT 1")
    user_row = cur.fetchone()
    if not user_row:
        cur.execute("SELECT id as user_id FROM lms_users LIMIT 1")
        user_row = cur.fetchone()
        
    uid = user_row["user_id"] if user_row else "dummy_123"
    print(f"Testing for user: {uid}")
    
    # 1. Course Progress
    cur.execute("""
        SELECT count(*) as total_assigned,
               count(*) FILTER (WHERE status = 'active') as total_started,
               count(*) FILTER (WHERE is_completed = true) as total_completed
        FROM lms_user_courses WHERE user_id=%s
    """, (uid,))
    course_stats = cur.fetchone()
    
    cur.execute("""
        SELECT c.id, c.title, c.thumbnail, uc.progress_percentage, uc.is_completed, uc.status
        FROM lms_user_courses uc
        JOIN lms_courses c ON c.id = uc.course_id
        WHERE uc.user_id=%s
    """, (uid,))
    courses = cur.fetchall()

    # 2. Session Progress
    cur.execute("""
        SELECT count(*) as total_completed
        FROM lms_session_progress WHERE user_id=%s AND completed=true
    """, (uid,))
    total_sessions_completed = cur.fetchone()["total_completed"]

    cur.execute("""
        SELECT count(s.id) as total_assigned
        FROM lms_user_courses uc
        JOIN lms_sessions s ON s.course_id = uc.course_id
        WHERE uc.user_id=%s
    """, (uid,))
    total_sessions_assigned = cur.fetchone()["total_assigned"]
    total_sessions_pending = total_sessions_assigned - total_sessions_completed if total_sessions_assigned else 0

    session_stats = {
        "completed": total_sessions_completed,
        "pending": total_sessions_pending,
        "overall_percentage": int((total_sessions_completed / total_sessions_assigned) * 100) if total_sessions_assigned > 0 else 0
    }

    # 3. Quiz Analytics
    cur.execute("""
        SELECT qa.id, qa.score, qa.passed, qa.responses, qa.created_at,
               q.title, q.questions, q.passing_score
        FROM lms_quiz_attempts qa
        JOIN lms_quizzes q ON q.id = qa.quiz_id
        WHERE qa.user_id=%s
        ORDER BY qa.created_at DESC
    """, (uid,))
    quiz_attempts = cur.fetchall()
    
    quizzes_attempted = len(quiz_attempts)
    quizzes_passed = len([q for q in quiz_attempts if q["passed"]])
    
    detailed_quizzes = []
    for q in quiz_attempts:
        responses = q["responses"] or {}
        questions = q["questions"] or []
        details = []
        for qst in questions:
            qid = qst.get("id")
            correct = qst.get("correctOption")
            selected = responses.get(qid)
            details.append({
                "question": qst.get("text"),
                "selected_answer": selected,
                "correct_answer": correct,
                "is_correct": str(selected) == str(correct)
            })
        detailed_quizzes.append({
            "id": q["id"],
            "title": q["title"],
            "score": q["score"],
            "passed": q["passed"],
            "date": q["created_at"].isoformat() if q["created_at"] else None,
            "details": details
        })
        
    quiz_stats = {
        "attempted": quizzes_attempted,
        "passed": quizzes_passed,
        "attempts": detailed_quizzes
    }

    # 4. Learning Path Progress
    cur.execute("""
        SELECT lp.id, lp.title, ulp.is_completed, ulp.status
        FROM lms_user_learning_paths ulp
        JOIN lms_learning_paths lp ON lp.id = ulp.path_id
        WHERE ulp.user_id=%s
    """, (uid,))
    learning_paths = cur.fetchall()

    # 5. Activity & Streak
    cur.execute("""
        SELECT DISTINCT DATE(created_at) as active_date
        FROM lms_session_progress 
        WHERE user_id=%s
        UNION
        SELECT DISTINCT DATE(created_at) as active_date
        FROM lms_quiz_attempts
        WHERE user_id=%s
        ORDER BY active_date DESC
    """, (uid, uid))
    active_dates_rows = cur.fetchall()
    active_dates = [row["active_date"] for row in active_dates_rows if row["active_date"]] if active_dates_rows else []
    
    total_active_days = len(active_dates)
    last_active_date = active_dates[0].isoformat() if active_dates else None
    
    current_streak = 0
    longest_streak = 0
    if active_dates:
        from datetime import date, timedelta
        today = date.today()
        
        curr_date = today
        if active_dates[0] == today or active_dates[0] == today - timedelta(days=1):
            temp_streak = 0
            check_date = active_dates[0]
            i = 0
            while i < len(active_dates) and active_dates[i] == check_date:
                temp_streak += 1
                check_date -= timedelta(days=1)
                i += 1
            current_streak = temp_streak
            
        longest = 1
        current = 1
        for i in range(1, len(active_dates)):
            if active_dates[i-1] - active_dates[i] == timedelta(days=1):
                current += 1
                longest = max(longest, current)
            else:
                current = 1
        longest_streak = max(longest, longest_streak) if len(active_dates) > 0 else 0
        if longest_streak == 0 and len(active_dates) > 0:
            longest_streak = 1
            
    activity_stats = {
        "total_active_days": total_active_days,
        "last_active_date": last_active_date,
        "current_streak": current_streak,
        "longest_streak": longest_streak
    }

    res = {
        "course_progress": {
            "stats": course_stats,
            "courses": courses
        },
        "session_progress": session_stats,
        "quiz_analytics": quiz_stats,
        "learning_paths": learning_paths,
        "activity": activity_stats
    }
    print("SUCCESS!")
except Exception as e:
    import traceback
    traceback.print_exc()

