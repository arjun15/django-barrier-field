from django.apps import apps
from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import post_save
from django.dispatch import receiver

from barrier_field.client import cognito
from barrier_field.utils import get_attr_map, \
    get_custom_attrs_from_options, get_user_data_model, is_enabled, \
    get_user_data_model_fields


class User(AbstractUser):
    """
    Extend base django user to include phone number, which is required by
    cognito
    """
    phone_number = models.CharField(max_length=50, blank=True)

    user_data_model = getattr(settings, 'USER_DATA_MODEL', False)
    if user_data_model:
        user_data = models.ForeignKey(
            user_data_model, on_delete=models.CASCADE,
            blank=True, null=True
        )

    def sync_cognito(self, include_custom=False):
        user_data = self.__dict__
        cognito_data = {}
        for data in user_data.keys():
            # Remove default django stuff
            if data in [
                '_state', 'id', 'password', 'last_login', 'date_joined',
                'backend', '_password'
            ]:
                continue
            cognito_data[data] = user_data[data]

        cognito.username = cognito_data.pop('username')

        # Enable/disable cognito user based on 'is_active'
        if not cognito_data.pop('is_active'):
            cognito.admin_disable_user()
        else:
            cognito.admin_enable_user()

        # If user data model exists, remove foreign key from data
        if get_user_data_model():
            if include_custom:
                user_data_fields = self.sync_custom_data()
                cognito_data.update(user_data_fields)
            cognito_data.pop('user_data_id')

        cognito_data.update(**get_custom_attrs_from_options(cognito_data))
        cognito.admin_update_profile(
            cognito_data, attr_map=get_attr_map()
        )

    def sync_custom_data(self):
        data_model_fields = get_user_data_model_fields()
        additional_data = {}
        for field in data_model_fields:
            if field == 'id':
                continue
            field_value = getattr(self.user_data, field, False)
            if field_value:
                additional_data[field] = field_value
        return additional_data


@receiver(post_save)
def post_save_sync(sender, **kwargs):
    """
    Save data after user/user data model is saved
    """
    if is_enabled():
        if sender == get_user_data_model():
            User.objects.get(user_data__pk=kwargs['instance'].pk).sync_cognito(
                include_custom=True
            )
        if sender == User:
            User.objects.get(pk=kwargs['instance'].pk).sync_cognito()
