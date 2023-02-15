from django.urls import path
from . import views

urlpatterns = [
    path('isawake/', views.isAwake, name="isAwake"),
    path('user/register/', views.userRegister, name="userRegister"),
    path('user/login/', views.userLogin, name="userLogin"),

    path('task/create/', views.taskCreate, name="taskCreate")
]
