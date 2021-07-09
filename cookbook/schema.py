import graphql_jwt
import graphene
from graphene_django import DjangoObjectType
from graphene_django.types import validate_fields
from django.db.models import Q
from ingredients.models import Category, Ingredient
from django.contrib.auth.models import User

from graphql_auth.schema import UserQuery, MeQuery
from graphql_auth import mutations

class UserType(DjangoObjectType):
    class Meta:
        model = User

class CategoryType(DjangoObjectType):
    class Meta:
        model = Category
        fields = ("id", "name", "ingredients")

class IngredientType(DjangoObjectType):
    class Meta:
        model = Ingredient
        fields = ("id", "name", "notes", "category")

class Query(UserQuery, MeQuery, graphene.ObjectType):
    search_ingredients = graphene.List(IngredientType,search=graphene.String())
    all_user = graphene.List(UserType)
    all_category = graphene.List(CategoryType)
    all_ingredients = graphene.List(IngredientType)
    category_by_name = graphene.Field(CategoryType, name=graphene.String(required=True))

    def resolve_search_ingredients(self, info, search=None, **kwargs):
        # The value sent with the search parameter will be in the args variable
        if search:
            filter = (
                    Q(name__icontains=search) |
                    Q(notes__icontains=search)
            )
            return Ingredient.objects.filter(filter)

        return Ingredient.objects.all()

    def resolve_all_user(root, info):
        return User.objects.all()

    def resolve_all_ingredients(root, info):
        return Ingredient.objects.select_related("category").all()

    def resolve_all_category(root,info):
        return Category.objects.all()

    def resolve_category_by_name(root, info, name):
        try:
            return Category.objects.get(name=name)
        except Category.DoesNotExist:
            return None

# add data
class UserMutation(graphene.Mutation):
    class Arguments:
        username = graphene.String(required=True)
        first_name = graphene.String()
        last_name = graphene.String()
        email = graphene.String()
        password = graphene.String()

    user = graphene.Field(UserType)

    @classmethod
    def mutate(cls, root, info, **kwargs):
        user = User.objects.create(username=kwargs['username'], first_name=kwargs['first_name'],
                                   last_name=kwargs['last_name'], email=kwargs['email'], password = kwargs['password'])
        return UserMutation(user=user)


class CategoryMutation(graphene.Mutation):

    class Arguments:
        name = graphene.String(required=True)

    category = graphene.Field(CategoryType)

    @classmethod
    def mutate(cls, root, info, name):
        category = Category.objects.create(name=name)
        return CategoryMutation(category=category)

class IngredientMutation(graphene.Mutation):

    class Arguments:
        name = graphene.String(required=True)
        notes = graphene.String()
        category = graphene.ID(required=True)

    ingredient = graphene.Field(IngredientType)

    @classmethod
    def mutate(cls, root, info, name, notes, category):
        cat = Category.objects.get(pk=category)
        ingredient = Ingredient.objects.create(name=name, notes=notes, category=cat)
        return IngredientMutation(ingredient=ingredient)

# update
class UpdateCategoryMutation(graphene.Mutation):

    class Arguments:
        id = graphene.ID()
        name = graphene.String(required=True)

    category = graphene.Field(CategoryType)

    @classmethod
    def mutate(cls, root, info, id, name):
        category = Category.objects.get(pk=id)
        category.name=name
        category.save()
        return CategoryMutation(category=category)


class UpdateIngredientMutation(graphene.Mutation):
    class Arguments:
        id = graphene.ID(required=True)
        name = graphene.String(required=True)
        notes = graphene.String()
        category = graphene.ID(required=True)
    ingredient = graphene.Field(IngredientType)

    @classmethod
    def mutate(cls, root, info, **kwargs):
        cat = Category.objects.get(pk = kwargs['category'])
        ingredient = Ingredient.objects.get(pk=kwargs['id'])
        ingredient.name=kwargs['name']
        ingredient.notes=kwargs['notes']
        ingredient.category=cat
        ingredient.save()
        return IngredientMutation(ingredient=ingredient)

# Delete
class Delete_Category(graphene.Mutation):
    class Arguments:
        id = graphene.ID(required=True)

    category = graphene.Field(CategoryType)

    @classmethod
    def mutate(cls, root , info, id):
        cat = Category.objects.get(pk=id)
        cat.delete()
        return

class Delete_ingredient(graphene.Mutation):
    class Arguments:
        id = graphene.ID()

    ingredient = graphene.Field(IngredientMutation)

    @classmethod
    def mutate(cls, root,info, id):
        ingredient = Ingredient.objects.get(pk=id)
        ingredient.delete()
        return

class AuthMutation(graphene.ObjectType):
    register = mutations.Register.Field()
    verify_account = mutations.VerifyAccount.Field()
    token_auth = mutations.ObtainJSONWebToken.Field()
    update_account = mutations.UpdateAccount.Field()
    resend_activation_email = mutations.ResendActivationEmail.Field()
    send_password_reset_email = mutations.SendPasswordResetEmail.Field()
    password_reset = mutations.PasswordReset.Field()
    password_change = mutations.PasswordChange.Field()
    delete_account = mutations.DeleteAccount.Field()

    # archive_account = mutations.ArchiveAccount.Field()

    #
    # send_secondary_email_activation = mutations.SendSecondaryEmailActivation.Field()
    # verify_secondary_email = mutations.VerifySecondaryEmail.Field()
    # swap_emails = mutations.SwapEmails.Field()

   # django-graphql-jwt inheritances

    verify_token = mutations.VerifyToken.Field()
    refresh_token = mutations.RefreshToken.Field()
    revoke_token = mutations.RevokeToken.Field()


class Mutation(AuthMutation, graphene.ObjectType):
    # delete_token_cookie = graphql_jwt.DeleteJSONWebTokenCookie.Field()
    #
    # # Long running refresh tokens
    # delete_refresh_token_cookie = graphql_jwt.DeleteRefreshTokenCookie.Field()

    # add_user = UserMutation.Field()
    add_category = CategoryMutation.Field()
    add_ingredient = IngredientMutation.Field()

    update_category = UpdateCategoryMutation.Field()
    update_ingredient = UpdateIngredientMutation.Field()

    delete_category = Delete_Category.Field()
    delete_ingredinet = Delete_ingredient.Field()

schema = graphene.Schema(query=Query, mutation=Mutation)

