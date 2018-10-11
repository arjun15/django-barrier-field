import logging
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import post_save
from django.dispatch import receiver
import swapper

from barrier_field.client import cognito
from barrier_field.utils import (get_attr_map, get_custom_attrs_from_options,
                                 get_user_data_model, is_enabled, get_user_data_model_fields)

logger = logging.getLogger(__name__)


# BaseParent
class BaseUserData(models.Model):
    class Meta:
        abstract = True


class UserData(BaseUserData):
    class Meta:
        swappable = swapper.swappable_setting('barrier_field', 'UserData')


class User(AbstractUser):
    """
    Extend base django user to include phone number, which is required by
    cognito
    """
    phone_number = models.CharField(max_length=50, blank=True)
    user_data = models.ForeignKey(
        swapper.get_model_name('barrier_field', 'UserData'),
        on_delete=models.CASCADE, blank=True, null=True
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

        # Sync custom data
        user_data_fields = self.sync_custom_data()
        cognito_data.update(user_data_fields)
        # Remove foreign key id from user data model
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
    logger.debug('BarrierField -> Post sync save')
    if is_enabled():
        if sender == get_user_data_model():
            try:
                User.objects.get(
                    user_data__pk=kwargs['instance'].pk
                ).sync_cognito(include_custom=True)
            except ObjectDoesNotExist:
                # User data created first, so for new users
                # this will not exist yet
                pass
        if sender == User:
            User.objects.get(pk=kwargs['instance'].pk).sync_cognito()
