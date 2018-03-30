# Author: BigRabbit
#  下午1:10


def create_token(token_model, user, serializer):
    token, _ = token_model.objects.get_or_create(user=user)
    return token
