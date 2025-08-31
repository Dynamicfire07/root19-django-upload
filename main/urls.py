from django.urls import path
from . import views

urlpatterns = [
    path('',views.home, name='home'),
    path('get-subtopics/', views.get_subtopics, name='get_subtopics'),
    path('practice-questions/', views.practice_questions, name='practice_questions'),
    path('check-answer/', views.check_answer, name='check_answer'),
    path('update-activity/', views.update_activity, name='update_activity'),
    path('question-bank/', views.question_bank, name='question_bank'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('staff/user-activity/', views.user_activity_admin, name='user_activity_admin'),
]
