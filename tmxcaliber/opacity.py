import os
import re
import copy
import sys
import base64
import zlib
import argparse
from pathlib import Path
from urllib.parse import unquote
from collections import defaultdict

from bs4 import BeautifulSoup as bsoup

OPACITY_PERCENT = 10
BS4_BACKEND = 'xml'
CURR_DIR = Path(__file__).parent


def decompress(original_soup, bs4_backend='xml'):
    """
    tries to decompress contents in `diagram` tag if it's compressed;
    replaces contents of `diagram` with decoded/decompressed data inplace

    :param original_soup BS4: BS4 object of the source file/markup
    :param bs4_backend str: backend of BS4
    """
    diagram_tag = original_soup.select_one('diagram')
    if diagram_tag:
        decoded_string = base64.b64decode(diagram_tag.text.strip())

        decompressed_string = str()
        is_decompressed = False
        try:
            decompressed_string = unquote(zlib.decompress(
                decoded_string, -zlib.MAX_WBITS
            ).decode('utf-8'))
            is_decompressed = True
        except Exception:
            pass

        # remove current contents of diagram tag and
        # move decompressed markup into it
        if is_decompressed:
            diagram_tag.clear()
            diagram_tag.append(bsoup(decompressed_string, bs4_backend))

def make_validation(soup):
    """
    makes validation over formats of `feature_class` & `threat` values;
    raises an error if it doesn't pass

    :param soup BS4: default BS4 object of source file
    """
    object_tags = soup.select('object')

    # -> "threat" attribute is either:
    #   non-represent,
    #   empty,
    #   one item "FCx_Ty",
    #   a comma-seperated list of FCx_Ty,
    #   or FCx_all (where x,y are numbers)
    FCx_Ty_re = re.compile(r'^FC\d+_T\d+$')
    FCx_all_re = re.compile(r'^(FC\d+_)*all$')
    error_list = []
    
    for tag in object_tags:
        threat = tag.get('threat')
        if not threat:
            continue
        threat_list = threat.strip().split(',')
        for threat_entry in threat_list:
            if not FCx_Ty_re.search(threat_entry) and \
                    not FCx_all_re.search(threat_entry):
                error_list.append(f'Incorrect threat value: {threat}')

    # -> "feature_class" is either:
    #   non-represent,
    #   empty,
    #   one item "FCx",
    #   a comma-seperated list of FCx,
    #   or all (where x,y are numbers)
    FCx_re = re.compile(r'^((,?FC\d+)|(,?all))+$')
    for tag in object_tags:
        feature_class = tag.get('feature_class')
        if not feature_class:
            continue
        feature_class = feature_class.strip()
        if not FCx_re.search(feature_class):
            error_list.append(f'Incorrect feature_class value: {feature_class}')

    if error_list:
        for error in error_list:
            print(error)
        sys.exit(1)

def FCx_do_hide(curr_fc_value, object_tag):
    """
    detects: should tag to be hided or not; returns bool

    :param curr_fc_value str: FCx value
    :param object_tag BS4: object tag of XML file
    """
    feature_class = object_tag.get('feature_class', '').strip().split(',')    
    threat_list = object_tag.get('threat', '').strip().split(',')
    
    if curr_fc_value in feature_class:
        return False

    if 'all' in feature_class:
        return False

    for threat in threat_list:
        if threat == 'all':
            return False
        threat_fc_value = threat.split('_')[0]
        fc_all = '%s_all' % threat_fc_value
        if curr_fc_value == threat_fc_value or fc_all == threat:
            return False

    return True

def FCx_Ty_do_hide(curr_t_value, object_tag):
    """
    detects: should tag be hidden or not; returns bool
    (almost the same as FCx_do_hide function; take a look at it)

    :param curr_t_value str: Ty value
    :param object_tag BS4: object tag of XML file
    """
    # must be hidden if there's no `threat` attr at all
    threat = object_tag.get('threat')

    if not threat:
        return True

    threat = threat.strip().split(',')
    curr_fc_value = curr_t_value.split('_')[0]
    key2 = '%s_all' % curr_fc_value

    if curr_t_value not in threat and \
            'all' not in threat and key2 not in threat:
        return True

    return False

def make_tags_gray(tags):
    """
    adds textOpacity/opacity to tags to make them gray (inplace)

    :param tags list: list of BS4 objects (tags) to hide
    """
    for tag in tags:
        if not tag.get('style'):
            continue
        tag['style'] += ';textOpacity={0};opacity={0};'.format(OPACITY_PERCENT)

def generate_FCx_files(original_soup, fcx_tx_values, dest_dir, prefix_service):
    """
    generates new XML files based on an original one; makes gray
    objects/mxcells that haven't FCx value and saves new file into dest_dir

    :param original_soup BS4 object: default BS4 object of original file
    :param fcx_tx_values dict: dict of FCx/Tx values
    :param dest_dir Path: location to save the files to
    """
    output_filename_tpl = prefix_service + '_{fc_value}.xml'

    fc_value_list = []
    for fc_value in fcx_tx_values.get('FC', []):
        fc_value_list.append(fc_value)
    for t_value in fcx_tx_values.get('T', []):
        curr_fc_value = t_value.split('_')[0]
        if curr_fc_value not in fc_value_list and curr_fc_value != 'all':
            fc_value_list.append(curr_fc_value)

    for fc_value in fc_value_list:
        soup = copy.copy(original_soup)

        # mx cells tags to be hided:
        #   we must include root > mxCell tags here (w/o any condition)
        mxcell_tags_to_hide = soup.select('root > mxCell')

        object_tags = soup.select('root > object')
        for object_tag in object_tags:
            if FCx_do_hide(fc_value, object_tag):
                mxcell_tags = object_tag.select('mxCell')
                mxcell_tags_to_hide.extend(mxcell_tags)

        # make gray all of them (inplace)
        make_tags_gray(mxcell_tags_to_hide)

        # and write out the data
        output_filename = (
            dest_dir / Path(output_filename_tpl.format(fc_value=fc_value))
        ).absolute()
        with open(output_filename, 'w') as fp:
            fp.write(soup.prettify())
            print(f'Created {output_filename_tpl.format(fc_value=fc_value)}')

def generate_FCx_Ty_files(
    original_soup,
    fcx_tx_values,
    dest_dir,
    prefix_service
):
    """
    generates new XML files based on an original one; makes gray
    objects/mxcells that haven't FCx_Ty values and saves new file into dest_dir

    :param original_soup BS4: BS4 object of original file
    :param dest_dir Path: firectory to save the output files to
    """
    # the new files will be generated based on these ones
    output_filename_tpl = prefix_service + '_{t_value}.xml'
    for t_value in fcx_tx_values['T']:
        if 'all' in t_value:
            continue
        soup = copy.copy(original_soup)

        # mx cells tags to be hided:
        #   we must include root > mxCell tags here (w/o any condition)
        mxcell_tags_to_hide = soup.select('root > mxCell')

        object_tags = soup.select('root > object')
        for object_tag in object_tags:
            if FCx_Ty_do_hide(t_value, object_tag):
                mxcell_tags = object_tag.select('mxCell')
                mxcell_tags_to_hide.extend(mxcell_tags)

        # make gray all of them (inplace)
        make_tags_gray(mxcell_tags_to_hide)

        # and write out the data
        output_filename = (
            dest_dir / Path(output_filename_tpl.format(t_value=t_value))
        ).absolute()
        with open(output_filename, 'w') as fp:
            fp.write(soup.prettify())
            print(f'Created {output_filename_tpl.format(t_value=t_value)}')

def get_all_FCx_Tx_values(source_soup):
    """
    returns all possible FCx & Tx values defined in source XML file 
    (source_soupobject)

    :param source_soup BS4: default BS4 object of source XML file
    """
    object_tags = source_soup.select('object')

    values = list()
    for tag in object_tags:
        splitted = list()

        threat = tag.get('threat')
        if threat:
            splitted = list(map(str.strip, threat.split(',')))

        feature_class = tag.get('feature_class')
        if feature_class:
            splitted += list(map(str.strip, feature_class.split(',')))

        for chunk in splitted:
            chunk = chunk if isinstance(chunk, list) else [chunk]
            values.extend(chunk)

    # now construct dict we actually need
    ret_dict = defaultdict(set)
    for v in values:
        if '_' in v:
            update_key = 'T'
        elif v == 'all':
            continue
        else:
            update_key = 'FC'
        ret_dict[update_key].add(v)

    # returns in format:
    # {
    #     'FC': {'FC1', 'FC2', ...}
    #     'T': {'FC1_T1', 'FC3_T2', ...}
    # }
    return ret_dict

def generate(data, service_prefix, threat_dirname, fc_dirname, validate=False):

    threat_dir = Path(threat_dirname)
    fc_dir = Path(fc_dirname)
    threat_dir.mkdir(exist_ok=True)
    fc_dir.mkdir(exist_ok=True)

    # decompress it firstly (INPLACE!) (at least try)
    # if it's compressed (contents of diagram tag)
    bsobj = bsoup(data, BS4_BACKEND)
    decompress(bsobj, BS4_BACKEND)

    # make validation before
    if validate:
        make_validation(bsobj)

    # get all FCx/Tx values defined in the file
    fcx_tx_values = get_all_FCx_Tx_values(bsobj)

    # generate new ...FCx.xml files based on FCx values found
    generate_FCx_files(bsobj, fcx_tx_values, fc_dirname, service_prefix)

    # generate new ...FCx_Ty.xml files based on FCx/Tx values found
    generate_FCx_Ty_files(bsobj, fcx_tx_values, threat_dirname, service_prefix)

def main():

    parser = argparse.ArgumentParser(description='draw.io tool')
    parser.add_argument('input_filename', help='Source XML filename')
    parser.add_argument(
        '--threat-dir',
        default=CURR_DIR,
        help='Directory to output threat files to (default ./)',
    )
    parser.add_argument(
        '--fc-dir',
        default=CURR_DIR,
        help='Directory to output threat files to (default ./)',
    )
    parser.add_argument(
        '--validate',
        default=False,
        action='store_true',
        help='Flag indicating whether do validation or not',
    )

    args = parser.parse_args()
    filename = args.input_filename

    if not os.path.exists(filename):
        sys.exit(f'{filename} does not exist. Aborting.')
    if not os.path.isfile(filename):
        sys.exit(f'{filename} is not a file. Aborting.')

    with open(filename) as fp:
        generate(fp.read(), str(filename)[:-4], args.threat_dir, args.fc_dir)
