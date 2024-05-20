rule FlsAlloc
{
    strings:
        $my_text_string = "FlsAlloc"



    condition:
        $my_text_string
}
