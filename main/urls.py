from django.urls import path
from . import views

urlpatterns = [
    path('',views.home, name='home'),
    path('about/', views.about, name='about'),
    path('terms/', views.terms, name='terms'),
    path('privacy/', views.privacy, name='privacy'),
    path('disclaimer/', views.disclaimer, name='disclaimer'),
    path('get-subtopics/', views.get_subtopics, name='get_subtopics'),
    path('practice-questions/', views.practice_questions, name='practice_questions'),
    path('check-answer/', views.check_answer, name='check_answer'),
    path('update-activity/', views.update_activity, name='update_activity'),
    path('question-bank/', views.question_bank, name='question_bank'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('staff/user-activity/', views.user_activity_admin, name='user_activity_admin'),
    path('report-bug/', views.report_bug, name='report_bug'),
    path('report-bug/thanks/', views.report_bug_thanks, name='report_bug_thanks'),
    path('staff/bugs/', views.staff_bug_list, name='staff_bug_list'),
    path('staff/bugs/<int:bug_id>/', views.staff_bug_detail, name='staff_bug_detail'),
]
