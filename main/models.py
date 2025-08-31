from django.db import models


class Question(models.Model):
    question_id = models.CharField(max_length=255, primary_key=True)
    session_code = models.CharField(max_length=100)
    session = models.CharField(max_length=100)
    year = models.IntegerField()
    paper_code = models.CharField(max_length=50)
    variant = models.CharField(max_length=50)
    file_question = models.TextField()
    subtopic = models.CharField(max_length=255)
    extracted_text = models.TextField()
    image_base64 = models.TextField()
    answer = models.TextField()

    class Meta:
        db_table = "questions"   



class User(models.Model):
    user_id = models.CharField(max_length=255, primary_key=True)
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)  # store hashes, not plaintext
    role = models.CharField(max_length=50)
    school = models.CharField(max_length=255)
    
    class Meta:
        db_table = "users"


class UserActivity(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    solved = models.BooleanField(default=False)
    correct = models.BooleanField(default=False)
    bookmarked = models.BooleanField(default=False)
    starred = models.BooleanField(default=False)
    times_viewed = models.IntegerField(default=0)
    time_started = models.DateTimeField(null=True, blank=True)
    time_took = models.DurationField(null=True, blank=True)

    class Meta:
        db_table = "user_activity"
