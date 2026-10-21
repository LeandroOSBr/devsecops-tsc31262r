output "instance_id" {
  description = "ID único da instância EC2 criada na AWS"
  value       = aws_instance.servidor_app.id
}

output "ami_utilizada" {
  description = "ID da imagem (AMI) do Ubuntu selecionada pelo filtro"
  value       = data.aws_ami.ubuntu.id
}
