from flask_restful import fields

category_fields = {"id": fields.Integer, "name": fields.String, "slug": fields.String}

product_fields = {
    "id": fields.Integer,
    "name": fields.String,
    "slug": fields.String,
    "price": fields.Float,
    "quantity": fields.Integer,
    "categories": fields.List(fields.Nested(category_fields)),
}
