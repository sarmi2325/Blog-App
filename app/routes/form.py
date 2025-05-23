##import required modules
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, FileField, SubmitField
from wtforms.validators import DataRequired, Optional
from flask_wtf.file import FileAllowed
from flask_ckeditor import CKEditorField

#define post form
class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = CKEditorField('Content', validators=[DataRequired()])  
    link = StringField('Optional Link', validators=[Optional()])
    is_public = SelectField('Visibility', choices=[('true', 'Public'), ('false', 'Private')], validators=[DataRequired()])
    image = FileField('Upload Image', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')])
    submit = SubmitField('Create')
