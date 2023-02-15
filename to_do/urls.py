from django.urls import path
from . import views

urlpatterns = [
    path('isawake/', views.isAwake, name="isAwake"),
    path('user/register/', views.userRegister, name="userRegister"),
    path('user/login/', views.userLogin, name="userLogin"),

    path('task/create/', views.taskCreate, name="taskCreate"),
    path('task/fetch/', views.taskFetch, name="taskFetch"),
    path('task/tick/<str:task_id>', views.taskTick, name="taskTick"),
    # path('task/delete/<str: task_id>', views.taskDelete, name="taskDelete")
]
